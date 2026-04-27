rev=$(shell git rev-parse --short HEAD)
date=$(shell date +%F-%H-%M)
runDir=${date}_${rev}
configDir=config
experiment = my_experiment
scanDataDir = data
exampleDataDir = data
jobs = 4

build:
	cd yodns; go build

install:
	cd yodns; go install

# This runs a minimal experiment to showcase how to use yodns and evaluate its results
# The experiment includes a scan, validation of the results, and an evaluation.
my_experiment: build
	mkdir -p ${scanDataDir}/data ${scanDataDir}/config ${scanDataDir}/validate ${scanDataDir}/zoneDeps
	# sudo setcap cap_net_raw=eip ./experiments # allows ICMP packets to be received
	cp -r ${configDir}/local/* ${scanDataDir}/config # copy config so we know which config was used for the run
	# ---------------------------------------------------------------------------------
	# -- THIS IS A MINIMAL RUN CONFIGURATION AND NOT INTENDED FOR LARGE SCALE SCANS! --
	# ---------------------------------------------------------------------------------
	cd ${scanDataDir}; cat ${CURDIR}/${scanDataDir}/config/targets_local.csv | ${CURDIR}/yodns/yodns scan --config=${CURDIR}/${scanDataDir}/config/runconfig.json5 --ipv4-only
	# Validate the output [optional]
	find ${scanDataDir}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns validate --in={} --out=${scanDataDir}/validate/{/..}.json.zst --zip "zst" --printnoerr
	# Count the number of zone dependencies
	find ${scanDataDir}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns zoneDependencies --in={} --out=${scanDataDir}/zoneDeps/{/..}.csv --print-header=0
	# Each resolution contains all the zones necessary for that resolution -
	# so if you have multiple resolutions, you might want to deduplicate the results.
	find ${scanDataDir}/zoneDeps/ -type f -name '*.csv' -exec cat {} + | sort -k1 -i -t',' > ${scanDataDir}/zoneDeps/zoneDeps_all_unique.csv