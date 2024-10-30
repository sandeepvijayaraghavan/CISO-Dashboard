CIS CHECK.sh
The Bash script is designed to automate the validation of security configurations for a firewall device named "Cong_Hoa_100F." It performs a series of checks on a configuration file to ensure compliance with best practices and security policies. The script includes functions for extracting filenames, formatting results in JSON, logging outcomes, and sending data to an Elasticsearch index for centralized analysis. Specific configuration checks address aspects like DNS settings, WAN management, security banners, firmware updates, and encryption practices. Some checks require manual verification. Although the script outlines various checks, it currently lacks the execution logic to run them against a configuration file, which needs to be added. Overall, the script aims to improve the firewall's security posture by ensuring adherence to established configurations, supporting the organization’s cybersecurity strategy.



Logstash.yml code
The provided Logstash code is used to set up a pipeline for ingesting syslog data, processing it, and sending the results to an Elasticsearch instance. It listens for syslog messages on port 5555 and uses a Ruby filter to extract key-value pairs from the message field, distinguishing the service key by creating a nested hash. All extracted fields are then stored back into the event. The processed data is forwarded to Elasticsearch at https://localhost:9200, with daily indices named fa-all-%{+YYYY.MM.dd}. The configuration includes SSL settings, with SSL enabled and verification turned off, as well as the use of a specific pipeline named "severity" and authentication details for accessing Elasticsearch. It is advisable to uncomment and configure the SSL certificate authorities and verification mode if SSL verification is required and to replace the placeholder username and password with actual credentials. Overall, this Logstash setup effectively parses syslog messages and securely transmits the relevant data to Elasticsearch for further storage and analysis.


Threat Intel.py
The provided Python code defines an ElasticConnector class designed to integrate with OpenCTI and Elasticsearch. Upon initialization, it sets up a connection to OpenCTI, verifies the presence of a Live Stream ID, and retrieves the platform URL from OpenCTI settings. Depending on the configured mode (either "ecs", "ecs_no_signals", or "stix"), it initializes different managers for handling intelligence imports and sightings. The _connect_elasticsearch method establishes a connection to Elasticsearch using either basic authentication or an API key, ensuring only one authentication method is used at a time.
The class includes methods to handle the creation, updating, and deletion of indicators, processing messages received from the OpenCTI live stream. Each event is logged, and appropriate handler methods are called based on the event type. The start method initiates the listening process for incoming messages and manages shutdown procedures, including the graceful termination of background threads. Overall, this code facilitates the real-time integration of threat intelligence data into Elasticsearch for further analysis and monitoring within the OpenCTI framework.






