rev=$(shell git rev-parse --short HEAD)
date=$(shell date +%F-%H-%M)
runDir=${date}_${rev}

# General parameters: please change/verify BEFORE every test
Num_DNs = 10

# Scan parameters: check BEFORE running the run_scan target
inputFile = subfinder_example_${Num_DNs}.csv
inputLen = 10 # Number of DNs to read from input .csv file
parallelFiles = 1 # Number of output files created/written to at at time
fileSize = 50 # Number of target DN resolutions per output file

# Filtering/analysis parameters: check BEFORE running the run_scan target
# If filtering for a SINGLE batch: specify end points
Batch_start = 0
Batch_end = 1024

# COMMENT OUT IF A BATCH IS NOT BEING USED!!!!
#Batch = batch_${Batch_start}-${Batch_end}_output
# COMMENT OUT IF A BATCH IS NOT BEING USED!!!!

# General parameters for MULTI-BATCHING: please change/verify BEFORE every large test; each corresponding two numbers separated by a space are ends of a range
Batch_NOs = 0-1 2-3 4-5 6-9 # List all batches HERE (dashed ranges separated by a space):


# File configuration parameters: please check these are what you want BEFORE running any target!
# Make sure to comment out if you are not using batched subfolders!!!
# Output file directory
outSubDir = Output_${Num_DNs}_DN
folder = ${outputDir}/${outSubDir}
# Config and input file directory
configSubDir = capstone_config
config = ${configDir}/${configSubDir}


# No need to change/optional!
jobs = 4 # Number of parallel jobs for commands
configDir = config
outputDir = YoDNS_output
Batch ?=  #Allows the subfile path to be empty if a batch is not specified


# Given for provided experiment example
scanDataDir = config
exampleDataDir = data

build:
	cd yodns/yodns && go build 

# MAKEFILE TARGETS FOR A NON-BATCHED EXPERIMENT OR FILTERING OF A SINGLE BATCH____________________________________________________________________________________

# This runs a test of the capstone YoDNS configuration
# This includes the SCANNING portion of the experiment, producing binary (.pb.zst) output files for future analysis
run_scan: build 

	# Make folders to store scan results
	mkdir -p ${folder}/data ${folder}/config ${folder}/stats ${folder}/logs 
	# mkdir -p ${folder}/json ${folder}/validate #Optional files for testing/debugging

	# Prepare for scan
	sudo setcap cap_net_raw=eip ./yodns/yodns/yodns # allows ICMP packets to be received
	cp -r ${config}/* ${folder}/config # copy config so we know which config was used for the run
	
	# Run scan!
	cd ${folder}; ${CURDIR}/yodns/yodns/yodns scan --i=${CURDIR}/${config}/${inputFile} --len=${inputLen} --config=${CURDIR}/${config}/runconfig_capstone.json5  --threads 30 --ipv4-only --paraFiles ${parallelFiles} --s ${fileSize}
	
	# Validate the output [optional]
	# find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns validate --in={} --out=${folder}/validate/{/..}_Validate_Rec.json.zst --zip "zst" --printnoerr
	
	# Get stats on domains to check functionality/scan success
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns stats --in={} --out=${folder}/stats/{/..}_Stats.json.zst 

	# Convert to json format [optional]
	# find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns convertFormat --in={} --out=${folder}/json/{/..}.json.zst --zip "zst"
	
	
# This runs the capstone YoDNS configuration
# This includes the FILTERING of YoDNS results portion to extract only relevant records for identifying stale glue records, removing uneccessary information
filter_results_glue: build

	# Create organized folders for filtered output
	mkdir -p ${folder}/filtered/${Batch}/Auth/A_REC ${folder}/filtered/${Batch}/Auth/AAAA_REC ${folder}/filtered/${Batch}/Glue/A_Glue  ${folder}/filtered/${Batch}/Glue/AAAA_Glue 

	#Output Filtering:

	# Get authorized A and AAAA records
	find ${folder}/data/${Batch} -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={}  --out=${folder}/filtered/${Batch}/Auth/A_REC/{/..}_Auth_A_REC.json.zst  --aa --qtype=1 --rtype=1 --zip "zst"
	find ${folder}/data/${Batch} -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={} --out=${folder}/filtered/${Batch}/Auth/AAAA_REC/{/..}_Auth_AAAA_REC.json.zst  --aa --qtype=28 --rtype=28 --zip "zst"
	
	# Get A and AAAA glue records for NS queries
	find ${folder}/data/${Batch} -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={} --out=${folder}/filtered/${Batch}/Glue/A_Glue/{/..}_A_Glue.json.zst  --glue-only=true --qtype=2 --rtype=2 --glue-type=1 --zip "zst"
	find ${folder}/data/${Batch} -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={} --out=${folder}/filtered/${Batch}/Glue/AAAA_Glue/{/..}_AAAA_Glue.json.zst  --glue-only=true --qtype=2 --rtype=2 --glue-type=28 --zip "zst"


# This runs the capstone YoDNS configuration
# This includes the FILTERING of YoDNS results portion to extract only relevant records for identifying dangling CNAMEs, removing uneccessary information
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
	mkdir -p ${folder}/results/stale_glue  ${folder}/results/dangling_cname

	# Process filtered auth and glue record json files to identify stale glue records
	python3 ${CURDIR}/data_processing/process_glue.py ${Num_DNs}+${Batch}

	mkdir -p ${folder}/results/dangling_cname
	python3 ${CURDIR}/data_processing/process_cname.py \
		--cname-dir=${folder}/filtered/CNAME_REC \
		--output-dir=${folder}/results/dangling_cname


# This runs the capstone YoDNS configuration: helper target to merge results files from batches into one
merge_results: 

	#Merge files of the same type if multiple batches have been run
	python3 ${CURDIR}/data_processing/merge_files.py ${Num_DNs}


# Runs the entire experiment! Intended for smaller input datasets (>= 10k DNs)
pipeline: 
	$(MAKE) run_scan
	$(MAKE) filter_results_glue
	$(MAKE) filter_results_CNAME
	$(MAKE) analyze_results

# MAKE TARGETS FOR A NON-BATCHED EXPERIMENT____________________________________________________________________________________
# This runs a test of the capstone YoDNS MULTI BATCH configuration
# This includes the SCANNING portion of the experiment, producing binary (.pb.zst) output files for future analysis
run_scan_batch: build 

	# Make folders to store scan results
	mkdir -p ${folder}/data ${folder}/config ${folder}/stats ${folder}/logs 
	# mkdir -p ${folder}/validate #Optional files for testing/debugging

	# Prepare for scan
	sudo setcap cap_net_raw=eip ./yodns/yodns/yodns # allows ICMP packets to be received
	cp -r ${config}/* ${folder}/config # copy config so we know which config was used for the run
	
	# Run scan!
	cd ${folder}; ${CURDIR}/yodns/yodns/yodns scan --i=${CURDIR}/${config}/${inputFile} --len=${inputLen} --config=${CURDIR}/${config}/runconfig_capstone.json5  --threads 30 --ipv4-only --paraFiles ${parallelFiles} --s ${fileSize}
	
	# Validate the output [optional]
	# find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns validate --in={} --out=${folder}/validate/{/..}_Validate_Rec.json.zst --zip "zst" --printnoerr
	
	# Get stats on domains to check functionality/scan success
	find ${folder}/data -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns stats --in={} --out=${folder}/stats/{/..}_Stats.json.zst 

	# This loop created with the help of Gemini
	@for batch in ${Batch_NOs}; do \
		b1=$$(echo $$batch | cut -d'-' -f1); \
		b2=$$(echo $$batch | cut -d'-' -f2); \
		pb1=$$(printf "%08d" $$b1); \
		pb2=$$(printf "%08d" $$b2); \
		mkdir -p ${folder}/data/batch_$${b1}-$${b2}_output; \
		for i in $$(seq $$b1 $$b2); do \
        	pb=$$(printf "%08d" $$i); \
        	mv ${folder}/data/output_$${pb}_*.pb.zst ${folder}/data/batch_$${b1}-$${b2}_output/ 2>/dev/null || true; \
    	done; \
	done
	
# This runs the capstone YoDNS MULTI BATCH configuration
# This includes the FILTERING of YoDNS results portion to extract only relevant records for identifying stale glue records, removing uneccessary information
filter_results_batch: build

	# Create organized folders for filtered output
	@for batch in ${Batch_NOs}; do \
		mkdir -p ${folder}/filtered/batch_$${batch}_output/Auth/A_REC ${folder}/filtered/batch_$${batch}_output/Auth/AAAA_REC ${folder}/filtered/batch_$${batch}_output/Glue/A_Glue ${folder}/filtered/batch_$${batch}_output/Glue/AAAA_Glue; \
	done
	
	#Output Filtering:
	# Get authorized A and AAAA records, Get A and AAAA glue records for NS queries
	@for batch in ${Batch_NOs}; do \
		find ${folder}/data/batch_$${batch}_output -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={}  --out=${folder}/filtered/batch_$${batch}_output/Auth/A_REC/{/..}_Auth_A_REC.json.zst  --aa --qtype=1 --rtype=1 --zip "zst"; \
		find ${folder}/data/batch_$${batch}_output -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={} --out=${folder}/filtered/batch_$${batch}_output/Auth/AAAA_REC/{/..}_Auth_AAAA_REC.json.zst  --aa --qtype=28 --rtype=28 --zip "zst"; \
		find ${folder}/data/batch_$${batch}_output -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={} --out=${folder}/filtered/batch_$${batch}_output/Glue/A_Glue/{/..}_A_Glue.json.zst  --glue-only=true --qtype=2 --rtype=2 --glue-type=1 --zip "zst"; \
		find ${folder}/data/batch_$${batch}_output -type f -name 'output_*.zst' | parallel --jobs ${jobs} --plus ${CURDIR}/yodns/yodns/yodns extractMessagesCapstone --in={} --out=${folder}/filtered/batch_$${batch}_output/Glue/AAAA_Glue/{/..}_AAAA_Glue.json.zst  --glue-only=true --qtype=2 --rtype=2 --glue-type=28 --zip "zst"; \
	done

# This runs the capstone YoDNS configuration
# This includes the ANALYSIS of YoDNS results portion to process relevant records for identifying stale glue records
analyze_results_batch: build

	# Create output folders for analyzed data
	mkdir -p ${folder}/results/stale_glue  ${folder}/results/dangling_CNAMEs 

	#Output Filtering: Process filtered auth and glue record json files to identify stale glue records
	@for batch in ${Batch_NOs}; do \
		python3 ${CURDIR}/data_processing/process_glue.py ${Num_DNs}+batch_$${batch}_output; \
	done


# Runs the entire experiment! Intended for larger datasets to run in batches
# WARNING: running this pipeline does not delete output files along the way; ensure you have enough disk space or run targets individually
pipeline_batch: 
	$(MAKE) run_scan_batch
	$(MAKE) filter_results_batch
	$(MAKE) analyze_results_batch
	$(MAKE) merge_results


#PREVIOUS TESTS/METHODS_____________________________________________________________________________________________

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