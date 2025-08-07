FROM zeek/zeek-dev

RUN apt-get update && apt-get install --no-install-recommends -y \
	cmake \
	g++ \
	libpcap-dev \
	libssl-dev \
	make

WORKDIR /zeek-perf-support

COPY ./ .

RUN rm -rf build && ./configure && make
RUN cd testing && btest -d -j

RUN git config --global --add safe.directory $(pwd)
RUN git status .
RUN yes | zkg install .
RUN zeek -N Zeek::PerfSupport
RUN rm -f /tmp/perf-*.map
RUN zeek PerfSupport::enable=T -e 'event zeek_init() {}'
RUN cat /tmp/perf-*.map | grep zeek_init
