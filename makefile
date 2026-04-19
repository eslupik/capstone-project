rev=$(shell git rev-parse --short HEAD)
date=$(shell date +%F-%H-%M)
runDir=${date}_${rev}
configDir=config
outputDir = test_data
testDir = provided_test

experiment = my_experiment
scanDataDir = input_targets
exampleDataDir = data
jobs = 4

build:
	cd yodns/yodns && go build 

# This runs a minimal experiment to showcase how to use yodns and evaluate its results
# The experiment includes a scan, validation of the results, and an evaluation.
my_experiment: build 
	mkdir -p ${outputDir}/${testDir}
	mkdir -p ${outputDir}/${testDir}/data ${outputDir}/${testDir}/config ${outputDir}/${testDir}/validate ${outputDir}/${testDir}/zoneDeps
	# sudo setcap cap_net_raw=eip ./experiments # allows ICMP packets to be received
	cp -r ${configDir}/example_config/* ${outputDir}/${testDir}/config # copy config so we know which config was used for the run
	# ---------------------------------------------------------------------------------
	# -- THIS IS A MINIMAL RUN CONFIGURATION AND NOT INTENDED FOR LARGE SCALE SCANS! --
	# ---------------------------------------------------------------------------------
	cd ${outputDir}/${testDir}; cat ${CURDIR}/${scanDataDir}/example_target_1.csv | ${CURDIR}/yodns/yodns/yodns scan --config=${CURDIR}/${configDir}/example_config/runconfig.json5 --ipv4-only
	# Validate the output [optional]
	find ${outputDir}/${testDir}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns validate --in={} --out=${outputDir}/${testDir}/validate/{/..}.json.zst --zip "zst" --printnoerr
	# Count the number of zone dependencies
	find ${outputDir}/${testDir}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns zoneDependencies --in={} --out=${outputDir}/${testDir}/zoneDeps/{/..}.csv --print-header=0
	# Each resolution contains all the zones necessary for that resolution -
	# so if you have multiple resolutions, you might want to deduplicate the results.
	find ${outputDir}/${testDir}/zoneDeps/ -type f -name '*.csv' -exec cat {} + | sort -k1 -i -t',' > ${outputDir}/${testDir}/zoneDeps/zoneDeps_all_unique.csv