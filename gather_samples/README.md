# Regexp Sample Gathering System

This system scrapes the most popular npm packages for regular
expressions.


## Installation

`npm install`

## USAGE

`node index.js`


## Outputs

### `database.sqlite3` - Tables description

#### table `last_registry_update`

A singleton table which records when the global list of all available
packages was last updated.

| Column Name | Type | Description             |
|-------------|------|-------------------------|
| timestamp   | int  | Millis since unix epoch |

#### table `package`

Lists the name of all known packages.

| Column Name | Type | Description                                   |
|-------------|------|-----------------------------------------------|
| id          | text | the package name                              |
| key         | text | unused, taken from npm global package listing |
| revision    | text | unused, taken from npm global package listing |

#### table `package_downloads`

Lists the number of package downloads known for the window.

| Column Name | Type | Description                                                      |
|-------------|------|------------------------------------------------------------------|
| package_id  | text | References `package.id`                                          |
| start       | text | YYYY-MM-DD : start of download count window                      |
| end         | text | YYYY-MM-DD : end of download count window                        |
| downloads   | int  | The number of downloads seen by this package in the given window |

#### table `package_version`

Lits the chosen version to scrape

| Column Name | Type | Description                                                 |
|-------------|------|-------------------------------------------------------------|
| id          | int  | primary key                                                 |
| package_id  | text | References `package.id`                                     |
| version     | text | The version of the package which was scraped                |
| integrity   | text | The Subresource Integrity string for this version (see [1]) |
| sha1        | text | The sha1 for this version                                   |

#### table `regexps`

Lists the extracted regular expressions

| Column Name | Type | Description                                                             |
|-------------|------|-------------------------------------------------------------------------|
| id          | int  | primary key                                                             |
| pattern     | blob | utf8 binary blob of the regexp pattern                                  |
| flags       | blob | utf8 binary blob of the regexp flags (in practice this should be ascii) |
| count       | int  | number of times we've seen this regexp in all of the packages           |


#### table `skipped_files`

Lists the files that we couldn't parse for regexp literals

| Column Name        | Type | Description                                  |
|--------------------|------|----------------------------------------------|
| package_version_id | int  | References `package_version.id`              |
| file_name          | text | The path to the file that couldn't be parsed |



#### table `regexp_files`

Lists which regexps were extracted from what files

| Column Name | Type | Description  |
|-------------|------|-------------|
| id          | int  | primary key |
| regexps_id  | int  | References `regexps.id`|
| package_version_id | int | References `package_version.id` |
| file_path | text | The path to the in which this regexp was found |
| line_no_start | int | The line number of the start of the regexp literal |
| line_no_end | int | The line number of the end of the regexp literal (NOTE: this is likely equal to start) |
| column_no_start | int | The column number of the start of the regexp literal |
| column_no_end | int | The column number of the end of the regexp literal |


[1] https://w3c.github.io/webappsec-subresource-integrity/