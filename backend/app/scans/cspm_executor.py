import subprocess
import json
import os
import logging

logger = logging.getLogger("shieldscan")

def execute_prowler_scan():
    """
    Executes Prowler as a subprocess inside the Python virtual environment.
    Tries to capture JSON output directly to stream to DynamoDB.
    """
    # Path to the prowler executable inside the EC2 virtual environment
    prowler_bin = "/home/ubuntu/prowler_env/bin/prowler"
    
    # Simple check to verify if the binary exists in the current environment
    if not os.path.exists(prowler_bin):
        logger.warning(f"Prowler binary not found at {prowler_bin}. Running mock execution flow.")
        return None

    # Command parameters to run a targeted AWS scan and output clean JSON
    command = [
        prowler_bin,
        "aws",
        "--filter-severity", "HIGH,CRITICAL",
        "--output-modes", "json"
    ]

    try:
        logger.info("Initiating background Prowler process execution...")
        
        # Triggering the subprocess execution
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        
        # Parse the raw stdout string into a workable Python list
        report_data = json.loads(process.stdout)
        logger.info("Prowler process finished successfully.")
        return report_data

    except subprocess.CalledProcessError as e:
        logger.error(f"Process Execution Error: Code {e.returncode}")
        logger.debug(f"Stderr output: {e.stderr}")
        # CURRENTLY STUCK HERE: Subprocess is blocking the FastAPI event loop,
        # or failing due to missing active AWS STS credentials during the runtime check.
        raise e