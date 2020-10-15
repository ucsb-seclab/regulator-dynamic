// index.js
//
// Author: Robert McLaughlin <robert349@ucsb.edu>
//
// Scrapes the npm package registry for the most popular
// packages, then downloads the top 10,000 built distribution
// tarballs, and scans their content to extract regular
// expressions.


const { parse } = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const cliProgress = require('cli-progress');
const crypto = require('crypto');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const ssri = require('ssri');
const tar = require('tar');
const moment = require('moment');
const AbortController = require('abort-controller');
const yargs = require('yargs');
const { exit } = require('process');
const { Client } = require('pg');
const { Console } = require('console');


/**
 * Gets the absolute path to the locally cached package manifest
 * for the given package name.
 *
 * @param {string} baseDir
 * @param {string} packageName
 * @returns {string}
 */
function getManifestPath(baseDir, packageName) {
  return path.join(baseDir, `${encodeURIComponent(packageName)}.json`);
}


/**
 * Returns a Promise which resolves after the given timeout
 * @param {Number} ms how long to pause, in millis
 */
function resolveAfter(ms) {
  return new Promise((resolve) => setTimeout(() => resolve(), ms));
}


/**
 * Runs a sql query and resolves upon completion.
 *
 * No results are returned.
 *
 * @param {string} query the sql query
 */
function runSql(query) {
  return new Promise((resolve, reject) => {
    const db = getDatabase();
    db.run(query, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}


/**
 * Gets the global list of all packages from npm.
 * NOTE: this api _might_ be deprecated in the future: its existence
 * was difficult to find.
 *
 * @return {Promise<[{id: string, key: string, value: {"rev": string}}]}
 */
async function getAllPackages() {
  console.log('Gathering global list of all packages');

  const resp = await fetch(
    'https://replicate.npmjs.com/registry/_all_docs',
    {
      headers: { 'user-agent': 'npm package downloads scraper (contact robert349@ucsb.edu)' },
    },
  );

  const buffer = Buffer.alloc(1024 * 1024 * 200);
  let numRead = 0;
  let lastUpdated = 0;

  resp.body.on('data', (d) => {
    buffer.set(d, numRead);
    numRead += d.length;
    if (lastUpdated + 1000 * 5 < +new Date()) {
      console.log(`Downloaded ${Math.floor((numRead / 1024 / 1024) * 10) / 10}mb`);
      lastUpdated = +new Date();
    }
  });

  return new Promise((resolve, reject) => {
    resp.body.on('end', () => {
      const json = JSON.parse(buffer.subarray(0, numRead));
      resolve(json.rows);
    });
    resp.body.on('error', (e) => {
      console.error('Encountered error while fetching packages:', e);
      reject(e);
    });
  });
}


/**
 * Gets and stores (in the database) the list of all npm packages.
 */
async function getAndStorePackageListing() {
  const db = await getDatabase();

  // If there's any packages just assume we've done the download already
  const { rows: [{count}] } = await db.query('SELECT COUNT(*) FROM package');
  const numPackages = parseInt(count);

  if (numPackages !== 0)
  {
    console.log('Found package table full, skipping download');
    return;
  }

  const packages = await getAllPackages();

  console.log(`got ${packages.length} packages, inserting...`);

  await db.query('BEGIN TRANSACTION');

  const progressBar = new cliProgress.SingleBar({}, cliProgress.Presets.shades_classic);
  progressBar.start(packages.length, 0);

  for (let i=0; i < Math.ceil(packages.length / 1000); i++)
  {
    const iStart = i * 1000;
    const iEnd = i * 1000 + 999;
    const toInsert = packages.slice(iStart, iEnd + 1);
    await Promise.all(toInsert.map(({ id, key, value: { rev } }) => {
      return db.query(
        'INSERT INTO package (id, key, revision) VALUES ($1,$2,$3)',
        [id, key, rev]
      );
    }));
    progressBar.increment(toInsert.length);
  }

  await db.query('COMMIT');

  progressBar.stop();
  
  console.log(`committed ${packages.length} package rows`);
}


/**
 * Stores the download numbers for the known npm packages.
 *
 * VERY SLOW.
 */
async function getAndStorePackageDownloads(start, end) {
  const progressBar = new cliProgress.SingleBar({}, cliProgress.Presets.shades_classic);
  const db = await getDatabase();

  console.log('Getting list of package counts to query');

  // Get the list of packages we need to query
  /** @type {[string]} */
  const packageIds = await (async () => {
    const { rows } = await db.query(
      'SELECT p.id \
        FROM package p \
        LEFT JOIN (select * from package_downloads where start_dt = $1 AND end_dt = $2) pd \
          ON p.id = pd.package_id \
        WHERE pd.package_id is null \
      ',
      [start, end],
    );
    return rows.map(({ id }) => id);
  })();

  // exit early if there's nothing to be done here
  if (packageIds.length === 0)
  {
    console.log('No packages need download counts queried');
    return;
  }

  console.log(`found ${packageIds.length} that need package counts queried`);

  let insertsSinceCommit = 0;
  // async request processing loop
  const processMorePackages = async (queue, chunkSize, committer = false) => {
    if (queue.length === 0) {
      return;
    }
    const packagesToQuery = queue.splice(0, chunkSize);
    const httpQuery = encodeURIComponent(packagesToQuery.join(','));
    let json = null;

    // loop until we can get the json successfully
    for (;;) {
      const controller = new AbortController();
      const timeout = setTimeout(
        () => { controller.abort(); },
        30000 /* 30 seconds of timeout */,
      );
      try {
        const resp = await fetch(
          `https://api.npmjs.org/downloads/range/${encodeURIComponent(start)}:${encodeURIComponent(end)}/${httpQuery}`,
          {
            headers: { 'user-agent': 'npm package downloads scraper (contact robert349@ucsb.edu)' },
            signal: controller.signal,
          },
        );
        json = await resp.json();
        break;
      } catch (e) {
        if (e.name === 'AbortError' || e.type === 'aborted') {
          // expected -- this is a timeout
          await resolveAfter(10 * 1000 /* 10 sec */);
        }
        else if (e.type === 'invalid-json') {
          // expected -- this sometimes happens (don't know why)
          await resolveAfter(10 * 1000 /* 10 sec */);
        }
        else if (e.code === 'ETIMEDOUT' || e.code === 'ECONNRESET') {
          // expected -- pause for a bit and try again
          await resolveAfter(10 * 1000 /* 10 sec */);
        } else {
          console.error('caught', e);
          throw e;
        }
      }
      finally {
        clearTimeout(timeout);
      }
    }

    // great we got the json successfully
    const packageDownloadCounts = packagesToQuery.length === 1
      ? (() => {
        if (json.error && json.error.indexOf('not found') > 0) {
          // package not found, ignore it
          return [{ package: packagesToQuery[0], downloads: 0 }];
        }
        if (json.package !== packagesToQuery[0]) {
          console.log(json);
          throw new Error(`expected to find package ${packagesToQuery[0]} but got ${json.package}`);
        }
        let numDownloads = 0;
        json.downloads.forEach(({ downloads }) => {
          numDownloads += downloads;
        });
        return [{ package: json.package, downloads: numDownloads }];
      })()
      : packagesToQuery.map((packageName) => {
        if (json[packageName] === null) {
          // this is set when the package was deleted (?) so just ignore it
          return { package: packageName, downloads: 0 };
        } if (!json[packageName]) {
          throw new Error(`could not find package ${packageName}`);
        }
        let numDownloads = 0;
        json[packageName].downloads.forEach(({ downloads }) => {
          numDownloads += downloads;
        });
        return { package: packageName, downloads: numDownloads };
      });

    // const stmt = db.prepare('INSERT INTO package_downloads (package_id, start, end, downloads) VALUES (?,?,?,?)');
    for (const { package: packageName, downloads } of packageDownloadCounts) {
      await db.query(
        'INSERT INTO package_downloads (package_id, "start_dt", "end_dt", downloads) VALUES ($1,$2,$3,$4)',
        [packageName, start, end, downloads]
      );
      insertsSinceCommit += 1;
    }

    if (committer && insertsSinceCommit >= 5000) {
      await db.query('COMMIT; BEGIN TRANSACTION;');
      insertsSinceCommit = 0;
    }

    progressBar.increment(packageDownloadCounts.length);

    // wait just a bit before going back for more
    // Include some jitter to avoid the 'requests become synchronized' issue
    await resolveAfter(Math.random() * 500);

    await processMorePackages(queue, chunkSize, committer);
  };

  // 'scoped' packages (id looks like @foo/bar) are not supported in bulk query, so
  // broadly set aside those packages for later query
  const notScopedPackageIds = packageIds.filter((p) => p.indexOf('@') !== 0);
  const scopedPackageIds = packageIds.filter((p) => p.indexOf('@') === 0);

  if (notScopedPackageIds.length > 0) {
    console.log('fetching download rates for packages');
    progressBar.start(notScopedPackageIds.length, 0);

    await db.query('BEGIN TRANSACTION');

    await Promise.all([
      processMorePackages(notScopedPackageIds, 128),
      processMorePackages(notScopedPackageIds, 128, true),
    ]);

    await db.query('COMMIT');

    progressBar.stop();
  }

  if (scopedPackageIds.length > 0) {
    console.log('fetching download rates for scoped packages (SLOW)');
    progressBar.start(scopedPackageIds.length, 0);

    await db.query('BEGIN TRANSACTION');

    await Promise.all([
      processMorePackages(scopedPackageIds, 1),
      processMorePackages(scopedPackageIds, 1),
      processMorePackages(scopedPackageIds, 1),
      processMorePackages(scopedPackageIds, 1),
      processMorePackages(scopedPackageIds, 1, true),
    ]);

    await db.query('COMMIT');

    progressBar.stop();
  }
}


/**
 * Gets the package manifest (sometimes called 'packument') the top
 * 10,000 many packages, by downloads.
 *
 * @return {Promise}
 */
async function getAndStorePackageManifests(outputDir) {
  const numPackages = 10000;
  const db = await getDatabase();
  const basePath = path.resolve(outputDir, './manifests');
  const progressBar = new cliProgress.SingleBar({}, cliProgress.Presets.shades_classic);

  try
  {
    await fs.promises.stat(basePath);
  }
  catch (e)
  {
    if (e.code === 'ENOENT')
    {
      console.log(`creating path ${basePath}`);
      await fs.promises.mkdir(basePath);
    }
    else
    {
      throw e;
    }
  }

  // determine which package ids to query for
  /** @type {[{package_id: string}]} */
  const { rows: ids } = await db.query(
    'SELECT package_id FROM package_downloads ORDER BY downloads DESC LIMIT $1',
    [numPackages]
  );

  console.log('determining which packages need manifests downloaded');
  // figure out which ids we already know about
  const idsMaybeHaveManifest = await Promise.all(
    ids.map(async ({ package_id: packageId }) => {
      const manifestPath = getManifestPath(basePath, packageId);
      let exists = true;
      try {
        await fs.promises.stat(manifestPath);
      }
      catch (e)
      {
          if (e.code === 'ENOENT')
          {
            exists = false;
          }
          else
          {
            throw e;
          }
      }
      return { packageId, exists, manifestPath };
    }),
  );

  const idsWithoutManifest = idsMaybeHaveManifest.filter(({ exists }) => !exists);

  if (idsWithoutManifest.length === 0) {
    console.log('All manifests have been downloaded');
    return;
  }

  console.log(`found ${idsWithoutManifest.length} without manifest downloaded; downloading...`);

  progressBar.start(idsWithoutManifest.length, 0);

  const processMorePackages = async () => {
    if (idsWithoutManifest.length === 0) {
      return;
    }

    const { packageId: packageName, manifestPath } = idsWithoutManifest.pop();

    for (;;) {
      const controller = new AbortController();
      const timeout = setTimeout(
        () => { controller.abort(); },
        30000 /* 30 seconds of timeout */,
      );
      try {
        const resp = await fetch(
          `https://registry.npmjs.org/${encodeURIComponent(packageName)}`,
          {
            headers: { 'user-agent': 'npm package downloads scraper (contact robert349@ucsb.edu)' },
            signal: controller.signal,
          },
        );

        // save the file!
        const dest = fs.createWriteStream(manifestPath + '.tmp');
        resp.body.pipe(dest);
        await new Promise((resolve, reject) => {
          resp.body.on('end', resolve);
          resp.body.on('error', (err) => reject(err));
        });

        // file has been downloaded, remove the .tmp extension
        await fs.promises.rename(manifestPath + '.tmp', manifestPath);
        break;
      } catch (e) {
        if (e.name === 'AbortError' || e.type === 'aborted') {
          // expected -- this is a timeout
          await resolveAfter(10 * 1000 /* 10 sec */);
        }
        else if (e.type === 'invalid-json') {
          // expected -- this sometimes happens (don't know why)
          await resolveAfter(10 * 1000 /* 10 sec */);
        }
        else if (e.code === 'ETIMEDOUT' || e.code === 'ECONNRESET') {
          // expected -- pause for a bit and try again
          await resolveAfter(10 * 1000 /* 10 sec */);
        } else {
          console.error('caught', e);
          throw e;
        }
      }
      finally {
        clearTimeout(timeout);
      }
    }

    progressBar.increment(1);

    // wait just a bit before going back for more
    // Include some jitter to avoid the 'requests become synchronized' issue
    await new Promise((resolve) => setTimeout(resolve, Math.random() * 250));

    await processMorePackages();
  };

  await Promise.all([
    processMorePackages(),
    processMorePackages(),
    processMorePackages(),
    processMorePackages()]);

  progressBar.stop();
}


/**
 * Downloads the latest release tarball for the given package, or the
 * version stored in the `package_version` table, if present.
 *
 * Returns details about the finished download.
 *
 * @param {string} outputDir the output directory
 * @param {string} packageName the unique package id (should match a downloaded manifest)
 * @returns {Promise<{
 *    packageName: string,
 *    packagePath: string,
 *    version: string,
 *    integrity: string,
 *    sha1: string}>}
 */
async function downloadPackage(outputDir, packageName) {
  const manifestBasePath = path.resolve(outputDir, './manifests');
  const db = await getDatabase();

  // see if we have a target version for this recorded in the database already
  // (we do this to support restoring downloaded file directory if deleted)
  const { rows: existingVersionRows } = await db.query(
    'SELECT version, integrity, sha1 FROM package_version WHERE package_id = $1',
    [packageName]
  );

  if (existingVersionRows.length > 1)
  {
    // this is unexpected; we should only have _at most_ one result
    throw new Error(`Multiple package versions found for ${packageName}.`)
  }

  const manifestPath = getManifestPath(manifestBasePath, packageName);

  // sanity check for existence of manifest
  try
  {
    await fs.promises.stat(manifestPath);
  }
  catch (e)
  {
    if (e.code === 'ENOENT')
    {
      throw new Error(`could not find manifest for ${packageName}`);
    }
    throw e;
  }

  // parse the json & sanity check
  const content = await fs.promises.readFile(manifestPath, { encoding: 'utf8' });
  const json = JSON.parse(content);

  if (!json['dist-tags']) {
    throw new Error(`no active dists found for ${packageName}`);
  }

  if (existingVersionRows.length === 0)
  {
    // we'll need to use the 'latest' tag to determine which to download
    if (!json['dist-tags'].latest) {
      throw new Error(`could not find 'latest' dist-tag for ${packageName}`);
    }
  }

  const version =
    existingVersionRows.length === 1
      ? existingVersionRows[0].version
      : json['dist-tags'].latest;

  if (!json.versions) {
    throw new Error(`could not find dict of versions for ${packageName}`);
  }

  if (!json.versions[version]) {
    throw new Error(`could not find version spec for ${packageName}:${version}`);
  }

  const tarballUrl = json.versions[version].dist.tarball;
  const integrity = (
    json.versions[version].dist.integrity
    || ssri.fromHex(json.versions[version].dist.shasum, 'sha1')
  );

  if (!tarballUrl) {
    throw new Error(`could not find tarball url for ${packageName}:${version}`);
  }

  if (!integrity) {
    throw new Error(`could not find integrity info for ${packageName}:${version}`);
  }

  // set up the directory structure where the the tarball will be downloaded
  const tarballName = path.basename(new URL(tarballUrl).pathname);
  const tarballDestBasePath = path.resolve(
    outputDir,
    'tarballs',
    `${encodeURIComponent(packageName)}_${encodeURIComponent(version)}.tmp`,
  );

  await fs.promises.mkdir(tarballDestBasePath, { recursive: true });

  // download that tarball

  const tarballDestPath = path.join(tarballDestBasePath, tarballName + '.tmp');

  const resp = await fetch(
    tarballUrl,
    {
      headers: { 'user-agent': 'npm package downloader (contact robert349@ucsb.edu)' },
    },
  );

  const dest = fs.createWriteStream(tarballDestPath);
  resp.body.pipe(dest);
  await new Promise((resolve, reject) => {
    dest.on('finish', resolve);
    dest.on('error', (err) => reject(err));
    resp.body.on('error', (err) => reject(err));
  });

  // we have the tarball, check for integrity
  // NOTE: this rejects / throws on invalid integrity check
  try {
    await ssri.checkStream(
      fs.createReadStream(tarballDestPath),
      integrity,
    );
  } catch (e) {
    console.error('found:', e.found);
    console.error('expected:', e.expected);
    throw new Error(`could not verify integrity of ${packageName}`);
  }

  // untar the file
  await tar.x({
    file: tarballDestPath,
    cwd: tarballDestBasePath,
  });

  // compute sha1 of the tarball
  const sha1 = await new Promise((resolve, reject) => {
    const fd = fs.createReadStream(tarballDestPath);
    const hash = crypto.createHash('sha1');
    fd.on('error', (err) => reject(err));
    fd.on('end', () => resolve(hash.digest('hex')));
    fd.pipe(hash);
  });

  // if the tarball doesn't match what we expected, throw an error
  // because that seems wrong
  if (existingVersionRows.length === 1 && sha1 !== existingVersionRows[0].sha1)
  {
    throw new Error(`SHA1 did not match expectation for package ${packageName}:${version}`);
  }

  // delete the tarball (no reason to keep it)
  await fs.promises.unlink(tarballDestPath);

  // move the directory into place
  const tarballDestBasePathPermanent = path.resolve(
    outputDir,
    'tarballs',
    `${encodeURIComponent(packageName)}_${encodeURIComponent(version)}`,
  );
  await fs.promises.rename(tarballDestBasePath, tarballDestBasePathPermanent);

  return {
    packageName,
    packagePath: tarballDestBasePathPermanent,
    version,
    sha1,
    integrity,
  };
}

/**
 * Downloads and extracts the package contents of the top 10,000 most downloaded
 * packages.
 * 
 * Assumes manifests for these packages are already downloaded.
 * 
 * @param {string} outputDir 
 */
async function downloadAllPackages(outputDir) {
  const db = await getDatabase();

  const { rows: package_ids } = await db.query(
    ' \
      SELECT pd.package_id, pv.version \
      FROM package_downloads pd \
      LEFT JOIN package_version pv \
        ON pd.package_id = pv.package_id \
      ORDER BY downloads DESC LIMIT $1',
    [10000]
  );

  // figure out how many of these we need to download
  const packagesDownloaded = await Promise.all(
    package_ids.map(async ({package_id, version}) => {
      // if we don't know what version we need, assume we need to download it
      if (!version)
      {
        return {package_id, need_download: true};
      }

      // construct the directory we expect to see
      try
      {
        await fs.promises.stat(path.resolve(
          outputDir,
          'tarballs',
          `${encodeURIComponent(package_id)}_${encodeURIComponent(version)}`
        ));
      }
      catch (e)
      {
        if (e.code === 'ENOENT')
        {
          return {package_id, need_download: true};
        }
        throw e;
      }

      return {package_id, need_download: false};
    })
  );

  const packagesNeedingDownload = packagesDownloaded.filter(x => x.need_download);

  console.log(`Found ${packagesNeedingDownload.length} packages to download`);

  const progressBar = new cliProgress.SingleBar(
    { etaBuffer: 20 },
    cliProgress.Presets.shades_classic,
  );

  progressBar.start(packagesNeedingDownload.length, 0);

  async function downloadMore()
  {
    if (packagesNeedingDownload.length === 0)
    {
      return;
    }

    const { package_id } = packagesNeedingDownload.pop();
    const result = await downloadPackage(outputDir, package_id);

    progressBar.increment();

    await db.query(
      'INSERT INTO package_version (package_id, version, integrity, sha1) VALUES ($1,$2,$3,$4)',
      [package_id, result.version, result.integrity, result.sha1]
    );

    // wait a bit for cool-down
    await resolveAfter(500 + Math.random() * 500);
    await downloadMore();
  }

  await Promise.all([
    downloadMore(),
    downloadMore(),
  ]);
}

/**
 * Recursively examine `sourcesDir` for javascript files, and extract all
 * regular expressions discovered in them.
 * @param {string} sourcesDir path to sources directory
 * @return {Promise<{
 *        skipped: [string],
 *        regexps: [{
 *          pattern: string,
 *          flags: string,
 *          file: string,
 *          loc: {
 *            start: {line: number, column: number},
 *            end: {line: number, column: number}
 *          }
 *        }]}>}
 */
async function extractRegexpFromSources(sourcesDir) {
  // create a list of all .js files by search of directory tree
  const jsFiles = [];
  const dirsToExplore = [sourcesDir];
  while (dirsToExplore.length !== 0) {
    const dir = dirsToExplore.pop();
    const contents = await fs.promises.readdir(dir);

    for (const dirEntry of contents) {
      const dirEntryAbsolute = path.join(dir, dirEntry);
      // is this entry a directory (which we explore) or a file?
      const stat = await fs.promises.stat(dirEntryAbsolute);
      if (stat.isDirectory()) {
        dirsToExplore.push(dirEntryAbsolute);
      } else if (dirEntryAbsolute.endsWith('.js')) {
        jsFiles.push(dirEntryAbsolute);
      }
    }
  }

  const regexps = [];
  const skipped = [];
  // great, we have the files listed ... now tokenize and look for regexp
  for (const fname of jsFiles) {
    const relativeFile = path.relative(sourcesDir, fname);
    const jsContent = (await fs.promises.readFile(fname)).toString('utf8');
    // if >1mb-ish, skip (too big? idk, traverse never completes)
    if (jsContent.length > 1024 * 1024) {
      skipped.push(relativeFile);
      continue;
    }

    try {
      const ast = parse(jsContent, {
        plugins: ['jsx', 'flow', 'classProperties'],
        sourceType: 'unambiguous',
        allowReturnOutsideFunction: true,
      });
      traverse(ast, {
        RegExpLiteral: ({ node }) => {
          regexps.push({
            pattern: node.pattern,
            flags: node.flags,
            file: relativeFile,
            loc: { ...node.loc },
          });
        },
      });
    } catch (e) {
      skipped.push(relativeFile);
    }
  }

  return { regexps, skipped };
}


/**
 * Gets and stores all regexps in the most recent published version
 * of the given package.
 *
 * @param {string} packageId
 * @param {import('fs').WriteStream} output
 * @returns {Promise}
 */
async function getAndStorePackageRegexps(packageId, output) {
  const packageDownload = await downloadPackageLatest(packageId);
  const { regexps, skipped } = await extractRegexpFromSources(packageDownload.packagePath);
  const db = getDatabase();

  // remove left-over tarball files
  await fs.promises.rmdir(packageDownload.packagePath, { recursive: true });

  // let's assume this package/version has never been seen before,
  // and just insert a record anew (shouldn't hurt anyway)
  const stmt = db.prepare(
    `INSERT INTO package_version
    (package_id, version, integrity, sha1)
    VALUES (?,?,?,?)`,
  );
  /** @type {number} */
  const packageVersionDbId = await new Promise((resolve, reject) => {
    stmt.run([
      packageId,
      packageDownload.version,
      packageDownload.integrity.toString(),
      packageDownload.sha1,
    ],
    (err) => {
      if (err) reject(err);
      else resolve(stmt.lastID);
    });
  });
  stmt.finalize();

  const stmt2 = db.prepare(
    'INSERT INTO skipped_files (package_version_id, file_name) VALUES (?,?)',
  );

  for (const skip of skipped) {
    await new Promise((resolve, reject) => {
      stmt2.run([packageVersionDbId, skip], (err) => (err ? reject(err) : resolve()));
    });
  }

  for (const regexp of regexps) {
    const toWrite = `${[
      packageVersionDbId,
      Buffer.from(regexp.pattern).toString('base64'),
      Buffer.from(regexp.flags).toString('base64'),
      regexp.file,
      regexp.loc.start.line,
      regexp.loc.start.column,
      regexp.loc.end.line,
      regexp.loc.end.column,
    ].join(',')}\n`;
    output.write(Buffer.from(toWrite));
  }
}


/**
 * Download tarballs for all top 10k npm packaes, and
 * extract their regex literals into csv files.
 *
 * @return {Promise}
 */
async function getAndStoreAllPackageRegexps() {
  const db = getDatabase();
  const numPackages = 10000;
  /** @type {[{package_id: string}]} */
  const ids = await new Promise((resolve, reject) => {
    db.all(
      `SELECT package_id
          FROM (select * from package_downloads order by downloads desc limit ?)
          WHERE package_id NOT IN (SELECT package_id FROM package_version)
      `,
      numPackages,
      (err, rows) => {
        if (err) {
          setTimeout(() => reject(err), 0);
        } else {
          setTimeout(() => resolve(rows), 0);
        }
      },
    );
  });

  if (ids.length === 0) {
    return;
  }

  console.log('downloading packages to extract regexps');

  let nOutput = 1;
  const regexpsBasePath = path.join(__dirname, 'regexps');
  const pathForRegexpOutput = () => path.join(regexpsBasePath, `regexps.${nOutput}.csv`);

  if (!await new Promise((resolve) => fs.exists(regexpsBasePath, resolve))) {
    console.log('making regexps/ path');
    await fs.promises.mkdir(regexpsBasePath);
  }

  // find the next available .n.csv number `n`
  for (;;) {
    if (await new Promise((resolve) => fs.exists(pathForRegexpOutput(), resolve))) {
      nOutput += 1;
    } else {
      break;
    }
  }

  let output = fs.createWriteStream(
    pathForRegexpOutput(),
    {
      flags: 'a',
    },
  );

  const progressBar = new cliProgress.SingleBar(
    { etaBuffer: 20 },
    cliProgress.Presets.shades_classic,
  );
  progressBar.start(ids.length, 0);
  let nProcessed = 0;
  for (const { package_id: packageName } of ids) {
    await getAndStorePackageRegexps(packageName, output);
    nProcessed += 1;
    progressBar.increment(1);
    if (nProcessed >= 256) {
      // rotate to the next CSV file name for safety
      nOutput += 1;
      output.close();
      output = fs.createWriteStream(
        pathForRegexpOutput(),
        {
          flags: 'a',
        },
      );
      nProcessed = 0;
    }
  }
  progressBar.stop();

  const endAwaiter = new Promise((resolve) => output.on('finish', () => resolve()));

  output.close();

  await endAwaiter;
}


/**
 * Extract all unique regexps from the csv files.
 *
 * @return {Promise}
 */
async function buildRegexpDb() {
  // first list all .csv files to explore
  console.log('building regexp db');
  const csvsBasePath = path.join(__dirname, 'regexps');
  const fnames = await fs.promises.readdir(csvsBasePath);
  const csvFiles = fnames.filter((fname) => fname.endsWith('.csv'));

  const db = getDatabase();
  const progressBar = new cliProgress.MultiBar(
    { etaBuffer: 500 },
    cliProgress.Presets.shades_classic,
  );

  const bar1 = progressBar.create(csvFiles.length, 0, 'Overall');
  const bar2 = progressBar.create(0, 0);
  for (const csvFile of csvFiles) {
    const stat = await fs.promises.stat(path.join(csvsBasePath, csvFile));
    const fin = await fs.createReadStream(path.join(csvsBasePath, csvFile));
    const lineReader = readline.createInterface(fin);
    const regexpsToInsert = [];
    bar2.setTotal(stat.size);
    bar2.update(0);
    let i = 0;
    for await (const line of lineReader) {
      bar2.increment(line.length + 1);
      i += 1;
      const split = line.trim().split(',');
      const packageVersionId = parseInt(split[0]);
      const pattern = Buffer.from(split[1], 'base64');
      const flags = Buffer.from(split[2], 'base64');
      const filePath = split[3];
      const lineNoStart = parseInt(split[split.length - 4]);
      const lineNoEnd = parseInt(split[split.length - 2]);
      const colNoStart = parseInt(split[split.length - 3]);
      const colNoEnd = parseInt(split[split.length - 1]);
      regexpsToInsert.push({
        pattern,
        flags,
        packageVersionId,
        filePath,
        lineNoStart,
        lineNoEnd,
        colNoStart,
        colNoEnd,
      });
    }

    bar2.setTotal(regexpsToInsert.length);
    bar2.update(0);
    db.serialize();
    await runSql('begin transaction');
    let processed = 0;
    const stmt = db.prepare('INSERT INTO regexps (pattern, flags) VALUES (?,?)');
    for (const {
          pattern,
          flags,
          packageVersionId,
          filePath,
          lineNoStart,
          lineNoEnd,
          colNoStart,
          colNoEnd } of regexpsToInsert) {
      if (processed === 500) {
        await runSql('commit');
        await runSql('begin transaction');
        processed = 0;
      }
      processed += 1;
      // yay! let's insert I guess? first, does this thing exist
      let regexpId = await new Promise((resolve, reject) => {
        db.all(
          'SELECT id FROM regexps WHERE pattern = ? AND flags = ?',
          [pattern, flags],
          (err, rows) => {
            if (err) reject(err);
            else if (rows.length === 0) resolve(null);
            else resolve(rows[0].id);
          },
        );
      });

      // if it does not exist
      if (regexpId == null) {
        // insert new regexp
        regexpId = await new Promise((resolve, reject) => stmt.run(
          [pattern, flags],
          (err) => {
            if (err) reject(err);
            else resolve(stmt.lastID);
          },
        ));
      }

      await new Promise((resolve, reject) => db.run(
        (
          'INSERT INTO regexp_files (' +
            'regexps_id, ' +
            'package_version_id, ' +
            'file_path, ' +
            'line_no_start, ' +
            'line_no_end, ' +
            'column_no_start, ' +
            'column_no_end' +
          ') VALUES (?,?,?,?,?,?,?)'
        ),
        [
          regexpId,
          packageVersionId,
          filePath,
          lineNoStart,
          lineNoEnd,
          colNoStart,
          colNoEnd
        ],
        (err) => {
          if (err) {
            reject(err);
          }
          else {
            resolve();
          }
        }
      ));

      bar2.increment(1);
    }
    await new Promise((resolve, reject) => stmt.finalize((err) => {
      if (err) {
        reject(err);
      }
      else {
        resolve();
      }
    }));
    await runSql('commit');
    db.parallelize();
    bar1.increment();
  }
  progressBar.stop();
}


// ---------- main ---------------
const argv = yargs
  .scriptName('gather-npm-samples')
  .options({
    'start-date': {
      alias: 's',
      type: 'string',
      description: 'The start of the download-count window, YYYY-MM-DD',
      demandOption: true,
    },
    'end-date': {
      alias: 'e',
      type: 'string',
      description: 'The end of the download-count window, YYYY-MM-DD',
      demandOption: true,
    },
    'output-dir': {
      alias: 'o',
      type: 'string',
      description: 'The directory to place manifests and module contents',
      demandOption: true,
    },
    'pg-host': {
      type: 'string',
      description: 'The hostname of the postgres server to store metadata.\nDefault: $POSTGRES_HOST',
    },
    'pg-port': {
      type: 'integer',
      description: 'The port number of the postgres server.\nDefault: $POSTGRES_PORT',
    },
    'pg-database': {
      type: 'string',
      description: 'The postgres database to access.\nDefault: $POSTGRES_DB',
    },
    'pg-user': {
      type: 'string',
      description: 'The username of the postgres user.\nDefault: $POSTGRES_USER',
    },
    'pg-password': {
      type: 'string',
      description: 'The password of the postgres user.\nDefault: $POSTGRES_PASSWORD',
    },
  }).argv;


const datePat = /^\d{4}-\d{2}-\d{2}$/;

if (!argv.startDate.match(datePat))
{
  yargs.showHelp();
  console.error(`Improper date format: ${argv.startDate}`);
  exit(1);
}

if (!argv.endDate.match(datePat))
{
  yargs.showHelp();
  console.error(`Improper date format: ${argv.endDate}`);
  exit(1);
}

try
{
  const stat = fs.statSync(argv.outputDir);
  if (!stat.isDirectory())
  {
    yargs.showHelp();
    console.error(`Not a directory: ${argv.outputDir}`);
    exit(1);
  }
}
catch (e)
{
  if (e.code === 'ENOENT')
  {
    console.log(`WARNING: making directory ${argv.outputDir}`);
    fs.mkdirSync(argv.outputDir);
  }
}

console.log(`Using output directory: ${argv.outputDir}`);


if (!argv.pgHost)
{
  argv.pgHost = process.env["POSTGRES_HOST"];
}

if (!argv.pgPort)
{
  argv.pgPort = parseInt(process.env["POSTGRES_PORT"]);
}

if (!argv.pgDatabase)
{
  argv.pgDatabase = process.env["POSTGRES_DB"];
}

if (!argv.pgUser)
{
  argv.pgUser = process.env["POSTGRES_USER"];
}

if (!argv.pgPassword)
{
  argv.pgPassword = process.env["POSTGRES_PASSWORD"];
}

console.log(
  'Using Postgres connection: ' +
  `${argv.pgUser}@${argv.pgHost}:${argv.pgPort}/${argv.pgDatabase} ` +
  `(with password?: ${!!(argv.pgPassword)})`
);


/**
 * Opens and returns the database.
 *
 * If the schema is not initialized, performs that initialization.
 *
 * @return {Promise<import('pg').Client>}
 */
async function openDatabase() {
  const db = new Client({
    user:     argv.pgUser,
    password: argv.pgPassword,
    host:     argv.pgHost,
    port:     argv.pgPort,
    database: argv.pgDatabase,
  });

  console.debug('DEBUG: getting new database');

  await db.connect();
  
  await db.query('BEGIN TRANSACTION');

  await db.query(`
    CREATE TABLE IF NOT EXISTS package (
      id TEXT NOT NULL,
      key TEXT NOT NULL,
      revision TEXT NOT NULL
    )
  `);

  await db.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_package_id ON package (id)
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS package_downloads (
      package_id TEXT NOT NULL,
      start_dt TEXT NOT NULL,
      end_dt TEXT NOT NULL,
      downloads INTEGER
    )
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_package_downloads_package_id ON package_downloads(package_id)
  `)

  await db.query(`
    CREATE TABLE IF NOT EXISTS package_version (
      id SERIAL PRIMARY KEY,
      package_id TEXT NOT NULL,
      version TEXT NOT NULL,
      integrity TEXT NOT NULL,
      sha1 TEXT NOT NULL
    )
  `);

  await db.query('CREATE INDEX IF NOT EXISTS idx_package_version_package_id ON package_version (package_id)')

  await db.query('COMMIT');

  console.log('DEBUG: done getting new database');

  return db;
}


let globalDb = null;
/**
 * Gets the sqlite database, or opens a new one if one does
 * not yet exist.
 * @return {Promise<import('pg').Client>}
 */
async function getDatabase() {
  if (globalDb === null) {
    globalDb = await openDatabase();
  }
  return globalDb;
}


getAndStorePackageListing()
  .then(() => getAndStorePackageDownloads(argv.startDate, argv.endDate))
  .then(() => getAndStorePackageManifests(argv.outputDir))
  .then(() => downloadAllPackages(argv.outputDir))
  .then(async () => {
    await (await getDatabase()).end();
    console.log('done.');
  })
  .catch((e) => {
    console.error('ENCOUNTERED ERROR');
    console.error(e);
    exit(1);
  });

/*.then(() => getAndStorePackageDownloads())
  .then(() => getAndStorePackageManifests())
  .then(() => getAndStoreAllPackageRegexps())
  .then(() => buildRegexpDb())
  .then(() => {
    getDatabase().close();
    console.log('done.');
  })
  .catch((err) => {
    console.error('Error!!!!');
    console.error(err);
    getDatabase().close();
    process.exitCode = 1;
  });
*/
