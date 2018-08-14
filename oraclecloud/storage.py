#!/usr/bin/env python
#
# Waslley Souza
# 2018

import requests


class Storage:

    def __init__(self, username, password, identity_domain_id):
        self.__username = username
        self.__password = password
        self.__identity_domain_id = identity_domain_id
        self.__url_base = "https://" + self.__identity_domain_id + ".storage.oraclecloud.com"
        self.__url_auth = self.__url_base + "/auth/v1.0"
        self.__url_storage = self.__url_base + "/v1/Storage-" + self.__identity_domain_id + "/"

    #
    # Authentication
    #

    def authentication(self):
        headers = {
            'X-Storage-User': "Storage-" + self.__identity_domain_id + ":" + self.__username,
            'X-Storage-Pass': self.__password
        }

        response = requests.request("GET", self.__url_auth, headers=headers)
        return response.headers["X-Auth-Token"]

    #
    # Containers
    #

    def create_container(self, container_name):
        url = self.__url_storage + container_name

        headers = {
            'X-Auth-Token': self.authentication()
        }

        response = requests.request("PUT", url, headers=headers)
        return response.headers

    def delete_container(self, container_name):
        url = self.__url_storage + container_name

        headers = {
            "X-Auth-Token": self.authentication()
        }

        response = requests.request("DELETE", url, headers=headers)
        return response.headers

    def show_container_details_and_list_objects(self, container_name):
        url = self.__url_storage + container_name

        headers = {
            'X-Auth-Token': self.authentication()
        }

        response = requests.request("GET", url, headers=headers)
        return response.headers, response.text.splitlines()

    def show_container_metadata(self, container_name):
        url = self.__url_storage + container_name

        headers = {
            'X-Auth-Token': self.authentication()
        }

        response = requests.request("HEAD", url, headers=headers)
        return response.headers

    #
    # Objects
    #

    def create_or_replace_object(self, container_name, object_name, object_file):
        url = self.__url_storage + container_name + "/" + object_name

        headers = {
            'X-Auth-Token': self.authentication()
        }

        response = requests.request("PUT", url, data=object_file, headers=headers)
        return response.headers

    def create_or_update_object_metadata(self, container_name, object_name):
        url = self.__url_storage + container_name + "/" + object_name

        headers = {
            'X-Auth-Token': self.authentication()
        }

        response = requests.request("POST", url, headers=headers)
        return response.headers

    def delete_object(self, container_name, object_name):
        url = self.__url_storage + container_name + "/" + object_name

        headers = {
            'X-Auth-Token': self.authentication()
        }

        response = requests.request("DELETE", url, headers=headers)
        return response.headers

    def get_object_content_and_metadata(self, container_name, object_name):
        url = self.__url_storage + container_name + "/" + object_name

        headers = {
            'X-Auth-Token': self.authentication()
        }

        response = requests.request("GET", url, headers=headers, stream=True)
        return response.headers, response.content

    def show_object_metadata(self, container_name, object_name):
        url = self.__url_storage + container_name + "/" + object_name

        headers = {
            'X-Auth-Token': self.authentication()
        }

        response = requests.request("HEAD", url, headers=headers)
        return response.headers
