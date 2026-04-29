rev=$(shell git rev-parse --short HEAD)
date=$(shell date +%F-%H-%M)
runDir=${date}_${rev}

# General parameters: please change for every test
Num_DNs = 9295

# Scan parameters: check before running the scan commands
configSubDir = capstone_config
inputFile = subfinder_candidates_${Num_DNs}.csv
inputLen = 10000
parallelFiles = 30

configDir = config
outputDir = YoDNS_output

outSubDir = Output_${Num_DNs}_DN
folder = ${outputDir}/${outSubDir}
config = ${configDir}/${configSubDir}

# Given for provided experiment example
scanDataDir = config
exampleDataDir = data
jobs = 4

build:
	cd yodns/yodns && go build 

# This runs a test of the capstone YoDNS configuration
# This includes the SCANNING portion of the experiment, producing binary (.pb.zst) output files for future analysis
run_scan: build 

	# Make folders to store scan results
	mkdir -p ${folder}/data ${folder}/config ${folder}/stats ${folder}/logs 
	mkdir -p ${folder}/json ${folder}/validate #Optional files for testing/debugging

	# Prepare for scan
	sudo setcap cap_net_raw=eip ./yodns/yodns/yodns # allows ICMP packets to be received
	cp -r ${config}/* ${folder}/config # copy config so we know which config was used for the run
	
	# Run scan!
	cd ${folder}; ${CURDIR}/yodns/yodns/yodns scan --i=${CURDIR}/${config}/${inputFile} --len=${inputLen} --config=${CURDIR}/${config}/runconfig_capstone.json5  --threads 30 --ipv4-only --paraFiles ${parallelFiles}
	
	# Validate the output [optional]
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns validate --in={} --out=${folder}/validate/{/..}_Validate_Rec.json.zst --zip "zst" --printnoerr
	
	# Get stats on domains to check functionality/scan success
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns stats --in={} --out=${folder}/stats/{/..}_Stats.json.zst 

	# Convert to json format [optional]
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns convertFormat --in={} --out=${folder}/json/{/..}.json.zst --zip "zst"
	
	
# This runs the capstone YoDNS configuration
# This includes the FILTERING of YoDNS results portion to extract only relevant records for identifying stale glue records, removing uneccessary information
filter_results: build 

	# Create organized folders for filtered output
	mkdir -p ${folder}/filtered/Auth/A_REC ${folder}/filtered/Auth/AAAA_REC ${folder}/filtered/NS ${folder}/filtered/Glue/A_Glue  ${folder}/filtered/Glue/AAAA_Glue ${folder}/bucketized

	#Output grouping (bucketize by zone?? Currently doesn't work, don't uncomment)
	# find ${folder}/filtered/Auth/A_REC -type f -name 'output_*.json' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns bucketize --in={} --out=${folder}/bucketized --key=zone --buckets=10
	
	#Output Filtering:

	# Get authorized A and AAAA records
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={}  --out=${folder}/filtered/Auth/A_REC/{/..}_Auth_A_REC.json  --aa --qtype=1 --rtype=1
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={} --out=${folder}/filtered/Auth/AAAA_REC/{/..}_Auth_AAAA_REC.json  --aa --qtype=28 --rtype=28
	
	#Get A and AAAA glue records for NS queries
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={} --out=${folder}/filtered/Glue/A_Glue/{/..}_A_Glue.json  --glue-only=true --qtype=2 --rtype=2 --glue-type=1
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={} --out=${folder}/filtered/Glue/AAAA_Glue/{/..}_AAAA_Glue.json  --glue-only=true --qtype=2 --rtype=2 --glue-type=28

filter_results_CNAME: build
	# Create organized folders for filtered output
	mkdir -p ${folder}/filtered/CNAME_REC

	# Get authoritative CNAME records
	@for f in ${folder}/data/output_*.zst; do \
		[ -e "$$f" ] || { echo "No input files found in ${folder}/data"; exit 1; }; \
		base=$$(basename "$$f" .pb.zst); \
		${CURDIR}/yodns/yodns/yodns extractMessagesCapstone \
			--in="$$f" \
			--out="${folder}/filtered/CNAME_REC/$${base}_CNAME_REC.json" \
			--aa \
			--rtype=5; \
	done
# This runs the capstone YoDNS configuration
# This includes the ANALYSIS of YoDNS results portion to process relevant records for identifying stale glue records
analyze_results: build 

	# Create output folders for analyzed data
	mkdir -p ${folder}/results/stale_glue  ${folder}/results/dangling_CNAMEs 

	# Process filtered auth and glue record json files to identify stale glue records
	python3 ${CURDIR}/data_processing/process_glue.py ${Num_DNs}



#The old way of doing things...
extract_messages: build	

	# Ensure relevant output folder exists!
	mkdir -p ${folder}/data 
	# Create organized folders for filtered output
	mkdir -p ${folder}/extracted/Auth/A_REC ${folder}/extracted/Auth/AAAA_REC ${folder}/extracted/NS

	#Filter: Extract relevant rtypes
	# Get authorized A records
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessages --in={} --out=${folder}/extracted/Auth/A_REC/{/..}_Auth_A_REC.json.zst --zip "zst" --aa --qtype=1 --rtype=1
	
	#Get authorized AAAA records
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessages --in={} --out=${folder}/extracted/Auth/AAAA_REC/{/..}_Auth_AAAA_REC.json.zst --zip "zst" --aa --qtype=28 --rtype=28
	
	#Get NS records
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessages --in={} --out=${folder}/extracted/NS/{/..}_NS_REC.json.zst --zip "zst" --qtype=2 --rtype=2

# This runs a test of the capstone YoDNS configuration
# The experiment includes a scan, validation of the results, and (optionally) converts the output files to json format for visual inspection.
capstone_test: build 
	mkdir -p ${outputDir}/capstone_test
	mkdir -p ${outputDir}/capstone_test/data ${outputDir}/capstone_test/config ${outputDir}/capstone_test/validate ${outputDir}/capstone_test/json ${outputDir}/capstone_test/stats
	sudo setcap cap_net_raw=eip ./yodns/yodns/yodns # allows ICMP packets to be received
	cp -r ${configDir}/capstone_config/* ${outputDir}/capstone_test/config # copy config so we know which config was used for the run
	# Run scan!
	cd ${outputDir}/capstone_test; ${CURDIR}/yodns/yodns/yodns scan --config=${CURDIR}/${configDir}/capstone_config/runconfig_capstone.json5 --threads 30 --ipv4-only
	# Validate the output [optional]
	find ${outputDir}/capstone_test/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns validate --in={} --out=${outputDir}/capstone_test/validate/{/..}.json.zst --zip "zst" --printnoerr
	# Convert to json format [optional]
	find ${outputDir}/capstone_test/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns convertFormat --in={} --out=${outputDir}/capstone_test/json/{/..}.json
	#Get stats on domains to check functionality/scan success
	find ${outputDir}/capstone_test/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns stats --in={} --out=${outputDir}/capstone_test/stats/{/..}.json.zst 

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
	cd ${outputDir}; cat ${CURDIR}/${scanDataDir}/example_target_1.csv | ${CURDIR}/yodns/yodns/yodns scan --config=${CURDIR}/${configDir}/example_config/runconfig_capstone.json5 --ipv4-only
	# Validate the output [optional]
	find ${outputDir}/example_test/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns validate --in={} --out=${outputDir}/example_test/validate/{/..}.json.zst --zip "zst" --printnoerr
	# Count the number of zone dependencies
	find ${outputDir}/example_test/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns zoneDependencies --in={} --out=${outputDir}/example_test/zoneDeps/{/..}.csv --print-header=0
	# Each resolution contains all the zones necessary for that resolution -
	# so if you have multiple resolutions, you might want to deduplicate the results.
	find ${outputDir}/example_test/zoneDeps/ -type f -name '*.csv' -exec cat {} + | sort -k1 -i -t',' > ${outputDir}/example_test/zoneDeps/zoneDeps_all_unique.csv