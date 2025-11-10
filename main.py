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

        # Read as CSV (comma-delimited from source)
        csv_reader = csv.DictReader(io.StringIO(csv_data))
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
