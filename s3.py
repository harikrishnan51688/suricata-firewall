import boto3

s3 = boto3.client('s3',
            aws_access_key_id="",
            aws_secret_access_key="",
            region_name="us-east-1")

file_path = "custom_local.rules"
bucket_name = "suricata-rules-iitm"
object_name = "newfolder/custom_local.rules"

s3.upload_file(file_path, bucket_name, object_name)
print("Uploaded successfully!")
