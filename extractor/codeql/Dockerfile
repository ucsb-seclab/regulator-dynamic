from mcr.microsoft.com/cstsectools/codeql-container:latest

RUN python3 -m pip install psycopg2-binary psutil
RUN apt-get update && apt-get -y install nodejs && apt-get clean

ADD queries/ /opt/regulator/queries
ADD qlpack.yml /opt/regulator/qlpack.yml

RUN mkdir -p /opt/regulator/compilation_cache

RUN codeql query compile -v --compilation-cache=/opt/regulator/compilation_cache /opt/regulator/queries/constant_regexp_string_extraction.ql
RUN codeql query compile -v --compilation-cache=/opt/regulator/compilation_cache /opt/regulator/queries/regexp_literal.ql

# unfortunately we'll be running as nobody:nogroup, so chagne the owner of the cache & add a temp dir

RUN chown -R nobody:nogroup /opt/regulator/compilation_cache

RUN mkdir -p /tmp/regulator
RUN chown -R nobody:nogroup /tmp/regulator

ADD runner.py /opt/regulator/runner.py

ENTRYPOINT python /opt/regulator/runner.py
CMD []

