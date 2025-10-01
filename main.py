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
import schedule
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

# Channel ID for notifications (you can get this from Slack)
SLACK_CHANNEL = os.getenv('SLACK_CHANNEL', '#internal-tsi-feed-status')  # Default to #general

COLUMN_MAPPING = {
    'ID': 'id',
    'GTIN': 'gtin',
    'ITEM_GROUP_ID': 'item_group_id',
    'MPN': 'mpn',
    'IDENTIFIER_EXISTS': 'identifier_exists',
    'LINK': 'link',
    'IMAGE_LINK': 'image_link',
    'PRICE': 'price',
    'SALE_PRICE': 'sale_price',
    'SALE_PRICE_EFFECTIVE_DATE':'sale_price_effective_date',
    'AVAILABILITY': 'availability',
    'BRAND': 'brand',
    'COLOR': 'color',
    'CONDITION': 'condition',
    'SIZE': 'size',
    'PRODUCT_TYPE': 'product_type',
    'TITLE': 'title',
    'DESCRIPTION': 'description',
    'ADDITIONAL_IMAGE_LINK':'additional_image_link',
    'CUSTOM_LABEL_1': 'custom_label_1',
    'CUSTOM_LABEL_2': 'custom_label_2',
}

COLUMNS_TO_EXCLUDE = [
    'ad_exclude_override',
    'advertise_exclude',
    'margin',
    'margin_percentage',
    'status'
]

GOOGLE_COLUMN_ORDER_FULL = [
    'id', 'item_group_id', 'title', 'description', 'brand', 'link', 'image_link',
    'additional_image_link',
    'product_type', 'google_product_category', 'sale_price', 'sale_price_effective_date',
    'price', 'tax', 'shipping', 'mpn', 'gtin', 'condition', 'availability', 'shipping_weight',
    'age_group', 'gender', 'size', 'color', 'custom_label_0', 'custom_label_1',
    'custom_label_2', 'custom_label_3', 'custom_label_4', 'identifier_exists',
    'adwords_redirect', 'distressed', 'excluded_destination', 'link_redirect',
    'return_policy_label'
]

GOOGLE_COLUMN_ORDER = [
    col for col in GOOGLE_COLUMN_ORDER_FULL 
    if col in COLUMN_MAPPING.values()
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


def transform_csv_headers(csv_data):
    """Transform CSV headers from source format to Google Shopping format"""
    try:
        logger.info("Transforming CSV headers...")

        if isinstance(csv_data, bytes):
            csv_data = csv_data.decode('utf-8')

        csv_reader = csv.DictReader(io.StringIO(csv_data))
        original_headers = csv_reader.fieldnames
        logger.info(f"Original headers: {original_headers}")

        rows = list(csv_reader)
        logger.info(f"Found {len(rows)} data rows")

        output = io.StringIO()
        csv_writer = csv.DictWriter(output, fieldnames=GOOGLE_COLUMN_ORDER)
        csv_writer.writeheader()

        for row in rows:
            new_row = {}
            for source_col, target_col in COLUMN_MAPPING.items():
                if source_col in row and target_col not in COLUMNS_TO_EXCLUDE:
                    new_row[target_col] = row[source_col]

            for col in GOOGLE_COLUMN_ORDER:
                if col not in new_row and col not in COLUMNS_TO_EXCLUDE:
                    new_row[col] = ''

            csv_writer.writerow(new_row)

        transformed_csv = output.getvalue()
        output.close()

        logger.info(f"CSV transformed successfully! Excluded {len(COLUMNS_TO_EXCLUDE)} unwanted columns.")
        return transformed_csv, len(rows)

    except Exception as e:
        logger.error(f"Error transforming CSV: {e}")
        raise


def download_from_source():
    """Download CSV from source FTP server"""
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

        start_time = time.time()
        with sftp.open(SOURCE_CONFIG['filename'], 'r') as f:
            csv_data = f.read()
        
        download_time = time.time() - start_time
        logger.info(f"Downloaded {len(csv_data):,} bytes in {download_time:.2f} seconds")

        return csv_data

    except Exception as e:
        logger.error(f"Error downloading from source: {e}")
        raise
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()


def upload_to_google(csv_data):
    """Upload CSV to Google Shopping SFTP"""
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

        filename = "ams_google_shopping_feed.csv"
        start_time = time.time()

        with sftp.open(filename, 'w') as f:
            f.write(csv_data)

        upload_time = time.time() - start_time
        logger.info(f"Successfully uploaded {filename} to Google in {upload_time:.2f} seconds!")

        return upload_time

    except Exception as e:
        logger.error(f"Google upload error: {e}")
        raise
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()


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
