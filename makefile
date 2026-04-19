rev=$(shell git rev-parse --short HEAD)
date=$(shell date +%F-%H-%M)
runDir=${date}_${rev}
configDir=config
outputDir = test_data

experiment = capstone_test
scanDataDir = input_targets
exampleDataDir = data
jobs = 4

build:
	cd yodns/yodns && go build 

# This runs a minimal experiment to showcase how to use yodns and evaluate its results
# The experiment includes a scan, validation of the results, and an evaluation.
capstone_test: build 
	mkdir -p ${outputDir}/capstone_test
	mkdir -p ${outputDir}/capstone_test/data ${outputDir}/capstone_test/config ${outputDir}/capstone_test/validate ${outputDir}/capstone_test/json
	# sudo setcap cap_net_raw=eip ./yodns/yodns/yodns # allows ICMP packets to be received
	cp -r ${configDir}/capstone_config/* ${outputDir}/capstone_test/config # copy config so we know which config was used for the run
	# Run scan!
	cd ${outputDir}/capstone_test; cat ${CURDIR}/${scanDataDir}/example_target_1.csv | ${CURDIR}/yodns/yodns/yodns scan --config=${CURDIR}/${configDir}/capstone_config/runconfig_capstone.json5 --threads 30 --ipv4-only
	# Convert to json format [optional]
	find ${outputDir}/capstone_test/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns convertFormat --in={} --out=${outputDir}/capstone_test/json/{/..}.json --printnoerr
	

# This runs a minimal experiment to showcase how to use yodns and evaluate its results
# The experiment includes a scan, validation of the results, and an evaluation.
my_experiment: build 
	mkdir -p ${outputDir}/example_test
	mkdir -p ${outputDir}/example_test/data ${outputDir}/example_test/config ${outputDir}/example_test/validate ${outputDir}/example_test/zoneDeps
	# sudo setcap cap_net_raw=eip ./experiments # allows ICMP packets to be received
	cp -r ${configDir}/example_config/* ${outputDir}/example_test/config # copy config so we know which config was used for the run
	# ---------------------------------------------------------------------------------
	# -- THIS IS A MINIMAL RUN CONFIGURATION AND NOT INTENDED FOR LARGE SCALE SCANS! --
	# ---------------------------------------------------------------------------------
	cd ${outputDir}/example_test; cat ${CURDIR}/${scanDataDir}/example_target_1.csv | ${CURDIR}/yodns/yodns/yodns scan --config=${CURDIR}/${configDir}/example_config/runconfig_capstone.json5 --ipv4-only
	# Validate the output [optional]
	find ${outputDir}/example_test/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns validate --in={} --out=${outputDir}/example_test/validate/{/..}.json.zst --zip "zst" --printnoerr
	# Count the number of zone dependencies
	find ${outputDir}/example_test/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns zoneDependencies --in={} --out=${outputDir}/example_test/zoneDeps/{/..}.csv --print-header=0
	# Each resolution contains all the zones necessary for that resolution -
	# so if you have multiple resolutions, you might want to deduplicate the results.
	find ${outputDir}/example_test/zoneDeps/ -type f -name '*.csv' -exec cat {} + | sort -k1 -i -t',' > ${outputDir}/example_test/zoneDeps/zoneDeps_all_unique.csv