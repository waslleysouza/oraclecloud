#!/usr/bin/python3
# Waslley Souza (waslleys@gmail.com)
# 2018

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import base64
import time
import hmac
import hashlib
import platform
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from oraclecloud import Storage
import numpy as np
import os

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Iot:

    SIGNATURE_ALGORITHM = "SHA256withRSA"
    SECRET_HASH_ALGORITHM = "HmacSHA256"
    KEY_ALGORITHM = "RSA"
    KEY_FORMAT = "X.509"
    ACTIVATION_TOKEN = "HS256"
    MESSAGE_TOKEN = "RS256"


    def __init__(self, username, password, url_base, verify_ssl=True):
        self.__authorization = "Basic " + base64.b64encode(bytes(username + ":" + password, 'utf-8')).decode()
        self.__url_base = url_base
        self.__verify_ssl = verify_ssl
        self.__generate_rsa()


    def set_shared_secret(self, shared_secret):
        self.__shared_secret = bytes(shared_secret, 'utf-8')


    def create_device_model(self, name, urn, formats):
        headers = {
            'Content-Type': "application/json",
            'Accept': "application/json",
            'Authorization': self.__authorization
        }

        payload_formats = []
        for f in formats:
            print(f)
            formats_field = []
            for field in f['fields']:
                formats_field.append({
                    "name": field['name'],
                    "optional": field['optional'],
                    "type": field['type']
                })
            
            payload_formats.append({
                "urn": f['urn'],
                "name": f['name'],
                "type": f['type'],
                "value":{
                    "fields": formats_field
                }
            })

        payload = {
            "urn": urn,
            "name": name,
            "formats": payload_formats
        }

        response = self.__http_post("/iot/api/v2/deviceModels", json.dumps(payload), headers)
        return response.json() if response.status_code == 201 else None
        

    def get_device_model(self, urn):
        headers = {
            'Content-Type': "application/json",
            'Accept': "application/json",
            'Authorization': self.__authorization
        }

        response = self.__http_get("/iot/api/v2/deviceModels/" + urn, headers)
        return response.json() if response.status_code == 200 else None


    def get_device(self, id):
        header = {
            'Content-Type': "application/json",
            'Accept': "application/json",
            'Authorization': self.__authorization
        }

        response = self.__http_get("/iot/api/v2/devices/" + id, header)
        return response.json() if response.status_code == 200 else None


    def create_device(self, name, shared_secret, hardware_id, description=None, manufacturer=None,
                        model_number=None, serial_number=None):
        headers = {
            'Content-Type': "application/json",
            'Accept': "application/json",
            'Authorization': self.__authorization
        }
        
        self.__shared_secret = bytes(shared_secret, 'utf-8')

        payload = {
            "name": name,
            "hardwareId": hardware_id,
            "description": description,
            "manufacturer": manufacturer,
            "modelNumber": model_number,
            "serialNumber": serial_number,
            "sharedSecret": base64.b64encode(self.__shared_secret).decode()
        }

        response = self.__http_post("/iot/api/v2/devices", json.dumps(payload), headers)
        return response.json() if response.status_code == 201 else None


    def activate_device(self, device, device_model_urn):
        # self.__generate_rsa()
        activation_token = self.__get_token(device, self.ACTIVATION_TOKEN, "oracle/iot/activation")
        activation_policy = self.__get_activation_policy(device, activation_token)
        self.__direct_activation(device, device_model_urn, activation_token, activation_policy)


    def __get_token(self, device, algorithm=MESSAGE_TOKEN, scope=""):
        header = self.__get_jwt_header(algorithm)
        
        if algorithm == self.ACTIVATION_TOKEN:
            id = device["hardwareId"]
        else:
            id = device["id"]

        payload = self.__get_jwt_payload(id)
        client_assertion = self.__get_jwt_signature(device, header, payload, algorithm)

        form_data = \
            "grant_type=client_credentials" + \
            "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" + \
            "&client_assertion=" + client_assertion + \
            "&scope=" + scope

        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'Accept': "application/json"
        }

        response = self.__http_post("/iot/api/v2/oauth2/token", form_data, headers)
        return response.json() if response.status_code == 200 else None


    def __get_jwt_header(self, algorithm):
        headers = {
            "typ": "JWT",
            "alg": algorithm
        }

        return str(json.dumps(headers, separators=(',', ':')))


    def __get_jwt_payload(self, id):
        claims = {
            "iss": id,
            "aud": "oracle/iot/oauth2/token",
            "exp": int(time.time() + 15 * 60)
        }

        return str(json.dumps(claims, separators=(',', ':')))


    def __get_jwt_signature(self, device, header, payload, algorithm):
        encoded_header = base64.b64encode(bytes(header, 'utf-8')).strip(b"=").replace(b"+", b"-").replace(b"/", b"_")
        encoded_payload = base64.b64encode(bytes(payload, 'utf-8')).strip(b"=").replace(b"+", b"-").replace(b"/", b"_")
        client_assertion = b"".join([encoded_header, b".", encoded_payload])

        if algorithm == self.ACTIVATION_TOKEN:
            signature = hmac.new(self.__shared_secret, client_assertion, hashlib.sha256)
            signature = signature.digest()
        else:
            digest = SHA256.new(client_assertion)
            signer = PKCS1_v1_5.new(RSA.importKey(self.__private_key))
            signature = signer.sign(digest)

        encoded_signature = base64.b64encode(signature).strip(b"=").replace(b"+", b"-").replace(b"/", b"_")
        client_assertion = b"".join([client_assertion, b".", encoded_signature])
        return client_assertion.decode()


    def __get_activation_policy(self, device, activation_token):
        headers = {
            "Content-type": "application/json",
            "Accept": "application/json",
            "Authorization": activation_token["token_type"] + " " + activation_token["access_token"],
            "X-ActivationId": device["id"]
        }

        os_name = platform.system()
        os_version = platform.release()
        url = "/iot/api/v2/activation/policy" + "?OSName=" + os_name + "&OSVersion=" + os_version
        response = self.__http_get(url, headers)
        return response.json() if response.status_code == 200 else None


    def __generate_rsa(self):
        if os.path.isfile('private.pem'):
            f = open('private.pem', 'rb')
            self.__private_key = f.read()
            f.close()
        else:
            key_pair = RSA.generate(2048, e=65537)
            self.__private_key = key_pair.exportKey("PEM")
            f = open('private.pem', 'wb')
            f.write(key_pair.exportKey())
            f.close()


    def __direct_activation(self, device, device_model_urn, activation_token, activation_policy):
        headers = {
            "Content-type": "application/json",
            "Accept": "application/json",
            "Authorization": activation_token["token_type"] + " " + activation_token["access_token"],
            "X-ActivationId": device["id"]
        }

        private_key = RSA.importKey(self.__private_key)
        public_key = private_key.publickey().exportKey("DER")
        encoded_public_key = base64.b64encode(public_key)

        secret_hash = hmac.new(self.__shared_secret, bytes(device["id"], 'utf-8'), hashlib.sha256)
        payload = device["id"] + "\n" + self.KEY_ALGORITHM + "\n" + self.KEY_FORMAT + "\n" + self.SECRET_HASH_ALGORITHM + "\n"
        signature = b"".join([bytes(payload, 'utf-8'), secret_hash.digest(), public_key])

        digest = SHA256.new(signature)
        signer = PKCS1_v1_5.new(private_key)
        encoded_signature = base64.b64encode(signer.sign(digest))

        data = {
            "deviceModels": [
                "urn:oracle:iot:dcd:capability:direct_activation",
                device_model_urn
            ],
            "certificationRequestInfo": {
                "subject": device["id"],
                "subjectPublicKeyInfo": {
                    "algorithm": self.KEY_ALGORITHM,
                    "publicKey": encoded_public_key.decode(),
                    "format": self.KEY_FORMAT,
                    "secretHashAlgorithm": self.SECRET_HASH_ALGORITHM
                },
                "attributes": {}
            },
            "signatureAlgorithm": self.SIGNATURE_ALGORITHM,
            "signature": encoded_signature.decode()
        }

        response = self.__http_post("/iot/api/v2/activation/direct", json.dumps(data), headers)
        return response.json() if response.status_code == 200 else None


    def send_message(self, device, format_urn, data):
        message_token = self.__get_token(device)

        headers = {
            "Content-type": "application/json",
            "Accept": "application/json",
            "Authorization": message_token["token_type"] + " " + message_token["access_token"],
            "X-EndpointId": device["id"]
        }

        payload = {
            "source": device["id"],
            "priority": "LOW",
            "reliability": "BEST_EFFORT",
            "type": "DATA",
            "eventTime": int(time.time() * 1000),
            "payload": {
                "format": format_urn,
                "data": data
            }
        }

        self.__http_post("/iot/api/v2/messages", json.dumps(payload), headers)


    def create_storage_object(self, container_name, object_name, object_file):
        headers = {
            'Authorization': self.__authorization
        }
        
        response = self.__http_get("/iot/api/v2/provisioner/storage", headers)
        url = response['storageContainerUrl'] + "/" + container_name + "/" + object_name

        headers = {
            'X-Auth-Token': response['authToken']
        }

        self.__http_put(url, object_file, headers)
        return url


    def __http_post(self, url, data, headers):
        response = requests.request("POST", self.__url_base + url, data=data, headers=headers, verify=self.__verify_ssl)
        return response


    def __http_put(self, url, data, headers):
        response = requests.request("PUT", url, data=data, headers=headers, verify=self.__verify_ssl)
        return response


    def __http_get(self, url, headers):
        response = requests.request("GET", self.__url_base + url, headers=headers, verify=self.__verify_ssl)
        return response