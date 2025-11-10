import os
import paramiko
import hashlib
import base64
import csv
import io
import logging
from datetime import datetime
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import time
import pytz

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration from environment variables
SOURCE_CONFIG = {
    'hostname': os.getenv('SOURCE_HOSTNAME'),
    'port': int(os.getenv('SOURCE_PORT', 22)),
    'username': os.getenv('SOURCE_USERNAME'),
    'password': os.getenv('SOURCE_PASSWORD'),
    'filename': os.getenv('SOURCE_FILENAME')
}

GOOGLE_CONFIG = {
    'sftp_server': os.getenv('GOOGLE_SFTP_SERVER'),
    'sftp_port': int(os.getenv('GOOGLE_SFTP_PORT', 19321)),
    'username': os.getenv('GOOGLE_SFTP_USERNAME'),
    'password': os.getenv('GOOGLE_SFTP_PASSWORD'),
    'fingerprint': os.getenv('GOOGLE_FINGERPRINT')
}

# Slack configuration
SLACK_TOKEN = os.getenv('SLACK_BOT_TOKEN')
slack_client = WebClient(token=SLACK_TOKEN) if SLACK_TOKEN else None

# Channel ID for notifications
SLACK_CHANNEL = os.getenv('SLACK_CHANNEL', '#internal-tsi-feed-status')

# Columns to exclude from the final upload
COLUMNS_TO_EXCLUDE = [
    'ad_exclude_override',
    'advertise_exclude',
    'margin',
    'margin_percentage',
    'status',
    'tax'
]

# Google Shopping preferred column order
GOOGLE_COLUMN_ORDER = [
    'id', 'item_group_id', 'title', 'description', 'brand', 'link', 'image_link',
    'additional_image_link', 'product_type', 'google_product_category', 'sale_price',
    'sale_price_effective_date', 'price', 'tax', 'shipping', 'mpn', 'gtin',
    'condition', 'availability', 'availability_date', 'shipping_weight',
    'age_group', 'gender', 'size', 'color', 'custom_label_0', 'custom_label_1',
    'custom_label_2', 'custom_label_3', 'custom_label_4', 'identifier_exists',
    'adwords_redirect', 'distressed', 'excluded_destination', 'link_redirect',
    'return_policy_label'
]

def send_slack_success_message(timestamp, file_size, upload_time, rows_processed):
    """Send success message to Slack channel"""
    if not slack_client:
        logger.warning("Slack client not configured")
        return
    
    try:
        message = (
            f"✅ *Google Shopping Feed Updated Successfully*\n\n"
            f"📅 *Timestamp:* {timestamp}\n"
            f"📊 *File Size:* {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)\n"
            f"📦 *Products:* {rows_processed:,} items processed\n"
            f"⏱️ *Upload Time:* {upload_time:.2f} seconds\n"
            f"🎯 *Status:* Feed sync completed successfully"
        )
        
        slack_client.chat_postMessage(
            channel=SLACK_CHANNEL,
            text=message,
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                }
            ]
        )
        logger.info("Success message sent to Slack")
    except SlackApiError as e:
        logger.error(f"Error sending success message to Slack: {e.response['error']}")


def send_slack_error_message(error_message, timestamp):
    """Send error message to Slack channel with @channel mention"""
    if not slack_client:
        logger.warning("Slack client not configured")
        return
    
    try:
        message = (
            f"🚨 <!channel> *Google Shopping Feed Update Failed*\n\n"
            f"📅 *Timestamp:* {timestamp}\n"
            f"❌ *Error:* {error_message}\n"
            f"🔧 *Action Required:* Please check the feed sync process immediately"
        )
        
        slack_client.chat_postMessage(
            channel=SLACK_CHANNEL,
            text=message,
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                }
            ]
        )
        logger.info("Error message sent to Slack with @channel")
    except SlackApiError as e:
        logger.error(f"Error sending error message to Slack: {e.response['error']}")


def normalize_column_name(col):
    col = col.strip().lower()
    col = col.replace(' ', '_')
    return col

SPECIAL_MAPPINGS = {
    'weight': 'shipping_weight'
}

def transform_csv_headers(csv_data):
    """Transform CSV headers dynamically; keep all original columns, normalize names, and preserve data."""
    try:
        logger.info("Transforming CSV headers dynamically...")

        # Decode bytes if needed
        if isinstance(csv_data, bytes):
            csv_data = csv_data.decode('utf-8')

        # Read as TSV (tab-delimited from source)
        csv_reader = csv.DictReader(io.StringIO(csv_data), delimiter='\t')
        original_headers = csv_reader.fieldnames or []
        logger.info(f"Original headers: {original_headers}")

        # Normalize and remap columns automatically
        dynamic_columns = []
        for source_col in original_headers:
            normalized = normalize_column_name(source_col)
            target_col = SPECIAL_MAPPINGS.get(normalized, normalized)
            if target_col not in COLUMNS_TO_EXCLUDE:
                dynamic_columns.append(target_col)

        # Keep standard order first, then add any new ones
        ordered_columns = [c for c in GOOGLE_COLUMN_ORDER if c in dynamic_columns]
        remaining_columns = [c for c in dynamic_columns if c not in ordered_columns]
        final_columns = ordered_columns + remaining_columns

        # Log any unexpected new columns
        new_columns = [col for col in remaining_columns if col not in GOOGLE_COLUMN_ORDER]
        if new_columns:
            logger.info(f"🆕 Detected new columns not in default order: {new_columns}")

        output = io.StringIO()
        # Write as TSV (tab-delimited) with no quoting
        csv_writer = csv.DictWriter(
            output, 
            fieldnames=final_columns, 
            delimiter='\t', 
            quoting=csv.QUOTE_NONE, 
            escapechar='\\'
        )
        csv_writer.writeheader()

        rows_processed = 0
        for row in csv_reader:
            new_row = {}
            for source_col, value in row.items():
                normalized = normalize_column_name(source_col)
                target_col = SPECIAL_MAPPINGS.get(normalized, normalized)
                if target_col not in COLUMNS_TO_EXCLUDE:
                    # Remove any tab characters from field values to prevent column misalignment
                    if value:
                        value = value.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
                    new_row[target_col] = value

            # Only keep columns that actually exist in this row
            filtered_row = {col: new_row[col] for col in new_row if col in final_columns}
            csv_writer.writerow(filtered_row)
            rows_processed += 1

            if rows_processed % 1000 == 0:
                logger.info(f"Processed {rows_processed} rows...")

        transformed_csv = output.getvalue()
        output.close()

        logger.info(
            f"CSV transformed successfully! Processed {rows_processed:,} rows "
            f"and retained {len(final_columns)} columns."
        )

        return transformed_csv, rows_processed

    except Exception as e:
        logger.error(f"Error transforming CSV: {e}")
        raise


def download_from_source():
    """Download CSV from source FTP server in chunks"""
    ssh = None
    sftp = None

    try:
        logger.info(f"Connecting to source server {SOURCE_CONFIG['hostname']}:{SOURCE_CONFIG['port']}...")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh.connect(
            hostname=SOURCE_CONFIG['hostname'],
            port=SOURCE_CONFIG['port'],
            username=SOURCE_CONFIG['username'],
            password=SOURCE_CONFIG['password'],
            timeout=30
        )

        logger.info("Connected to source server!")
        sftp = ssh.open_sftp()
        logger.info("SFTP connection opened successfully")

        logger.info(f"Attempting to open file: {SOURCE_CONFIG['filename']}")
        
        # Get file size
        file_stats = sftp.stat(SOURCE_CONFIG['filename'])
        file_size = file_stats.st_size
        logger.info(f"File size: {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)")
        
        # Read the file in chunks
        logger.info("Starting to read file content in chunks...")
        start_time = time.time()
        
        remote_file = sftp.open(SOURCE_CONFIG['filename'], 'r')
        
        # Read in 10MB chunks to avoid memory issues
        chunk_size = 10 * 1024 * 1024  # 10 MB
        chunks = []
        bytes_read = 0
        
        while True:
            chunk = remote_file.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            logger.info(f"Read {bytes_read:,} / {file_size:,} bytes ({bytes_read/file_size*100:.1f}%)")
        
        remote_file.close()
        
        # Combine chunks
        logger.info("Combining chunks...")
        csv_data = b''.join(chunks)
        
        download_time = time.time() - start_time
        logger.info(f"Downloaded {len(csv_data):,} bytes in {download_time:.2f} seconds")

        return csv_data

    except Exception as e:
        logger.error(f"Error downloading from source: {e}")
        raise
    finally:
        if sftp:
            sftp.close()
            logger.info("SFTP connection closed")
        if ssh:
            ssh.close()
            logger.info("SSH connection closed")


def upload_to_google(csv_data):
    """Upload TSV to Google Shopping SFTP"""
    ssh = None
    sftp = None

    try:
        logger.info(f"Connecting to Google server {GOOGLE_CONFIG['sftp_server']}:{GOOGLE_CONFIG['sftp_port']}...")

        ssh = paramiko.SSHClient()

        class FingerprintPolicy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                expected_fingerprint = GOOGLE_CONFIG['fingerprint']
                key_bytes = key.asbytes()
                fingerprint = hashlib.sha256(key_bytes).digest()
                actual_fingerprint = f"SHA256:{base64.b64encode(fingerprint).decode()}"

                if actual_fingerprint != expected_fingerprint:
                    raise Exception(f"Host key verification failed!")
                logger.info("Host key verification passed!")

        ssh.set_missing_host_key_policy(FingerprintPolicy())

        ssh.connect(
            hostname=GOOGLE_CONFIG['sftp_server'],
            port=GOOGLE_CONFIG['sftp_port'],
            username=GOOGLE_CONFIG['username'],
            password=GOOGLE_CONFIG['password'],
            timeout=30
        )

        logger.info("Connected to Google server!")
        sftp = ssh.open_sftp()
        logger.info("SFTP connection to Google opened successfully")

        filename = "tsi_google_shopping_feed.txt"
        logger.info(f"Preparing to upload file: {filename}")
        logger.info(f"Upload file size: {len(csv_data):,} bytes ({len(csv_data) / 1024 / 1024:.2f} MB)")
        
        start_time = time.time()

        logger.info("Opening remote file for writing...")
        with sftp.open(filename, 'w') as f:
            logger.info("Writing data to remote file...")
            f.write(csv_data)
            logger.info("Data written successfully")

        upload_time = time.time() - start_time
        logger.info(f"Successfully uploaded {filename} to Google in {upload_time:.2f} seconds!")

        return upload_time

    except Exception as e:
        logger.error(f"Google upload error: {e}")
        raise
    finally:
        if sftp:
            sftp.close()
            logger.info("SFTP connection to Google closed")
        if ssh:
            ssh.close()
            logger.info("SSH connection to Google closed")


def sync_feed():
    """Main function to sync the feed"""
    pst = pytz.timezone('America/Los_Angeles')
    pst_time = datetime.now(pst)
    timestamp = pst_time.strftime("%Y-%m-%d %H:%M:%S PST")
    
    try:
        logger.info("=== Starting Feed Sync ===")
        
        # Download from source
        csv_data = download_from_source()
        
        # Transform CSV headers
        transformed_csv, rows_processed = transform_csv_headers(csv_data)
        
        # Upload to Google
        upload_time = upload_to_google(transformed_csv)
        
        # Send success notification
        send_slack_success_message(timestamp, len(transformed_csv), upload_time, rows_processed)
        
        logger.info("=== Feed sync completed successfully! ===")
        return True
        
    except Exception as e:
        error_message = str(e)
        logger.error(f"=== Feed sync failed: {error_message} ===")
        
        # Send error notification
        send_slack_error_message(error_message, timestamp)
        
        return False


def validate_config():
    """Validate that all required environment variables are set"""
    required_vars = [
        'SOURCE_HOSTNAME', 'SOURCE_USERNAME', 'SOURCE_PASSWORD', 'SOURCE_FILENAME',
        'GOOGLE_SFTP_SERVER', 'GOOGLE_SFTP_USERNAME', 'GOOGLE_SFTP_PASSWORD', 'GOOGLE_FINGERPRINT'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        return False
    
    logger.info("✓ All required environment variables are configured")
    return True


if __name__ == "__main__":
   logger.info("=== Google Shopping Feed Sync Worker Starting ===")
   
   # Validate configuration
   if not validate_config():
       logger.error("Configuration validation failed. Exiting.")
       exit(1)
   
   if SLACK_TOKEN:
       logger.info(f"✓ Slack notifications enabled for channel: {SLACK_CHANNEL}")
   else:
       logger.warning("⚠️ Slack notifications disabled (no SLACK_BOT_TOKEN)")
   
   # Run the sync once and exit
   logger.info("Running single sync...")
   success = sync_feed()

   if success:
       logger.info("✅ Sync completed successfully!")
   else:
       logger.error("❌ Sync failed!")
       exit(1)

   logger.info("=== Script completed ===")
