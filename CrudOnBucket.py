
import requests
import xmltodict as xmltodict
from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from requests.exceptions import RequestException, HTTPError, ConnectionError, Timeout
import json
import datetime
import hashlib
import hmac
import base64
import logging
import re
import config as con
from rgwadmin import RGWAdmin

app = Flask(__name__)
api = Api(app)


access_key = con.access_key
secret_key = con.secret_key
endpoint_url = con.endpoint_url

timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
common_headers = {
            'Host': endpoint_url,
            'Date': timestamp
        }




class BucketCreation(Resource):
    # This class will create bucket

    def put(self):
        # this function will create a bucket.
        try:

            if not request.data.strip():
                return {'error': 'Empty payload. Please provide the bucket name.'}, 400
            request_data = request.get_json()

            if request_data.get('bucket_name') is None:
                return {'bucket_name': 'This field is compulsory for creating bucket'}, 400

            bucket_name = request_data.get('bucket_name')
            # validating bucket name
            name = re.match(r'(?!.*[-.]{2})(?!.*-\.)',bucket_name)
            if name is None:
                return {"msg":"Please enter valid bucket name"}
            else:
                name = re.match(r'^[a-z0-9][a-z0-9\-.]{1,61}[a-z0-9]$', bucket_name)
                if name is None:
                    return {"msg": "Please enter valid bucket name"}

            url = f'{endpoint_url}/{bucket_name}'
            string_for_signature = f'PUT\n\n\n{timestamp}\n/{bucket_name}'
            signature = hmac.new(secret_key.encode('utf-8'), string_for_signature.encode('utf-8'), hashlib.sha1)
            signature = base64.b64encode(signature.digest()).decode('utf-8')

            auth_header = f'AWS {access_key}:{signature}'

            common_headers['Authorization'] = auth_header

            response = requests.put(url, headers=common_headers)

            if response.status_code == 200:
                return {"msg": f'Bucket {bucket_name} created successfully'}
            else:
                return {"Error": "An error occurred"}, response.status_code

        except Exception as e:
            logging.error(f'An error occurred: {str(e)}')
            return {'error': "Something went wrong. Please try again later"}, 500






class BucketList(Resource):

    #This class will list out all the buckets.
    def get(self):
        try:
            string_for_signature = f'GET\n\n\n{timestamp}\n/'
            signature = hmac.new(secret_key.encode('utf-8'), string_for_signature.encode('utf-8'), hashlib.sha1)
            signature = base64.b64encode(signature.digest()).decode('utf-8')

            auth_header = f'AWS {access_key}:{signature}'

            common_headers['Authorization'] = auth_header

            response = requests.get(endpoint_url + '/', headers=common_headers)

            if response.status_code == 200:
                dict_resp = xmltodict.parse(response.text)
                resp = dict_resp['ListAllMyBucketsResult']['Buckets']
                return resp
            else:
                return {"Error": "An error occurred"}, response.status_code

        except Exception as e:
            logging.error(f'An error occurred: {str(e)}')
            return {'error': "Something went wrong. Please try again later"}, 500

class BucketObjectHandler(Resource):
    # This class will List out bucket usage,
    # will put object in the bucket,
    # will delete bucket

    def get(self, bucket_name):
        # this function will list out bucket usage.
        try:
            url = f'{endpoint_url}/{bucket_name}'
            string_for_signature = f'GET\n\n\n{timestamp}\n/{bucket_name}'
            signature = hmac.new(secret_key.encode('utf-8'), string_for_signature.encode('utf-8'), hashlib.sha1)
            signature = base64.b64encode(signature.digest()).decode('utf-8')

            auth_header = f'AWS {access_key}:{signature}'

            common_headers['Authorization'] = auth_header

            response = requests.get(url, headers=common_headers)

            if response.status_code == 200:
                dict_resp = xmltodict.parse(response.text)
                li = []
                bucket_name = dict_resp['ListBucketResult']['Name']

                # checking for empty bucket
                if dict_resp['ListBucketResult'].get('Contents') is None:
                    return {bucket_name: li}

                contents = dict_resp['ListBucketResult'].get('Contents')
                for content in contents:
                    key = content.get('Key')
                    last_modified = content.get('LastModified')
                    size = content.get('Size')
                    li.append({'obj_name':key,'last_modified':last_modified,'size':size})

                return {bucket_name: li}
            elif response.status_code==404:
                return {"msg":"bucket doesn't exist"}
            else:
                print(response.text,"kehg")
                return {"error": "An error Occurred"},500

        except Exception as e:
            logging.error(f'error occurred:{str(e)}')
            return {"error": "Something went wrong. Please try again later"}, 500


    def put(self,bucket_name):
        # this function will upload object in the bucket
        try:
            print(request)
            # checking file is available or not
            if request.files.get('file') is None:
                return {"msg": "Please upload file"}, 400

            file = request.files.get('file')
            content_type = file.content_type
            object_name = file.filename

            file = file.read()

            #checking for bucket permission


            url = f'{endpoint_url}/{bucket_name}/{object_name}'

            string_for_signature = f'PUT\n\n{content_type}\n{timestamp}\nx-amz-acl:public-read\n/{bucket_name}/{object_name}'
            signature = hmac.new(secret_key.encode('utf-8'), string_for_signature.encode('utf-8'),hashlib.sha1)
            signature = base64.b64encode(signature.digest()).decode('utf-8')

            auth_header = f'AWS {access_key}:{signature}'

            common_headers['Authorization'] = auth_header
            common_headers['Content-type'] = content_type
            common_headers['x-amz-acl'] = 'public-read'

            # file = request.files.get('file')
            # file = file.read()
            print(url,common_headers,file,"jhedgy")

            response = requests.put(url, headers=common_headers, data=file)
            print(response.status_code)
            print(response.text)

            if response.status_code == 200:
                return {'msg': f'File {object_name} uploaded successfully. hit this url {url}'}
            else:
                return {'msg': 'An error occurred.Please try again!'}, response.status_code

        except Exception as e:
            logging.error(str(e))
            return {"error": "Something went wrong"}, 500



    def delete(self,bucket_name):
        # this function will delete bucket
        try:
            url = f'{endpoint_url}/{bucket_name}'
            string_for_signature = f'DELETE\n\n\n{timestamp}\n/{bucket_name}'
            signature = hmac.new(secret_key.encode('utf-8'), string_for_signature.encode('utf-8'), hashlib.sha1)
            signature = base64.b64encode(signature.digest()).decode('utf-8')

            auth_header = f'AWS {access_key}:{signature}'

            common_headers['Authorization'] = auth_header

            response = requests.delete(url, headers=common_headers)

            if response.status_code == 204:
                return {"msg": "bucket deleted successfully"}
            elif response.status_code == 404:
                return {"msg":f"The bucket {bucket_name} doesn't exist"}
            else:
                return {"msg": "Failed to delete bucket"}, response.status_code

        except Exception as e:
            logging.error(f'An error occurred: {str(e)}')
            return {'error': "Something went wrong. Please try again later"}, 500





class GetBucketACL(Resource):


    def get(self,bucket_name):
        # This function will fetch ACL of the bucket
        try:
            url = f'{endpoint_url}/{bucket_name}/?acl'
            string_for_signature = f'GET\n\n\n{timestamp}\n/{bucket_name}/?acl'
            signature = hmac.new(secret_key.encode('utf-8'), string_for_signature.encode('utf-8'), hashlib.sha1)
            signature = base64.b64encode(signature.digest()).decode('utf-8')

            auth_header = f'AWS {access_key}:{signature}'

            common_headers['Authorization'] = auth_header

            response = requests.get(url , headers=common_headers)

            if response.status_code == 200:
                dict_resp = xmltodict.parse(response.text)
                return dict_resp
            else:
                return {"Error": "An error occurred"}, response.status_code

        except Exception as e:
            logging.error(f'An error occurred: {str(e)}')
            return {'error': "Something went wrong. Please try again later"}, 500


class BucketPolicy(Resource):

    def put(self,bucket_name):
        # This function will Associate user with bucket and add CRUD permissions on the bucket for that user.
        try:
            request_data = request.get_json()
            user = request_data.get('user')

            url = f'{endpoint_url}/{bucket_name}/?policy'

            timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
            string_to_sign = f'PUT\n\n\n{timestamp}\n/{bucket_name}/?policy'
            signature = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
            signature = base64.b64encode(signature.digest()).decode('utf-8')

            authorization_header = f'AWS {access_key}:{signature}'

            headers = {
                'Host': endpoint_url,
                'Date': timestamp,
                'Authorization': authorization_header,
            }

            bucket_policy = {
                "Version": "2012-10-17",
                "Id": "S3Policy1",
                "Statement": [
                    {
                        "Sid": "BucketAllow",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": [f"arn:aws:iam:::user/{user}"]
                        },
                        "Action": [
                            "s3:PutObject",
                            "s3:GetObject",
                            "s3:ListBucket"
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{bucket_name}",
                            f"arn:aws:s3:::{bucket_name}/*"
                        ]
                    }
                ]
            }

            response = requests.put(url, headers=headers, data=json.dumps(bucket_policy))

            if response.status_code == 204:
                return {"msg" :f"Policy set successfully for the user {user}."}
            else:
                return {"error" : f"Failed to set Policy for user {user}"}, response.status_code

        except Exception as e:
            logging.error(f"failed to set policy: {str(e)}")
            return {"error":"Something went wrong! Please try again later."}


class SetBucketQuota(Resource):
    def put(self, bucket_name):
        try:
            request_data = request.get_json()
            if request_data.get('max_size_kb') is None:
                return {"max_size_kb":"This field is compulsory"}
            elif request_data.get('max_objects') is None:
                return {"max_objects": "This field is compulsory"}

            max_size = request_data.get('max_size_kb')
            max_obj = request_data.get('max_objects')


            admin = RGWAdmin(server=con.server, access_key=access_key, secret_key=secret_key, secure= False)

            admin.set_bucket_quota(uid ='gets', bucket=bucket_name, max_size_kb=max_size, max_objects=max_obj)


            return {'message': f'Bucket {bucket_name} quota set successfully.'}, 200

        except Exception as e:
            logging.error(f"failed {str(e)}")
            return {'error': str(e)}, 500

# Add resource to the API
api.add_resource(SetBucketQuota, '/bucket/<string:bucket_name>/quota')





api.add_resource(BucketList, '/buckets')
api.add_resource(BucketObjectHandler, '/bucket/<string:bucket_name>')
api.add_resource(BucketCreation, '/bucket')
api.add_resource(GetBucketACL, '/bucket/<string:bucket_name>/acl')
api.add_resource(BucketPolicy, '/bucket/<string:bucket_name>/policy')
# api.add_resource(BucketObjects, '/<string:bucket_name>/<string:object_name>')
#api.add_resource(SetBucketObject,'/<string:bucket_name>/max-keys')
app.run(debug=True, port=5000)