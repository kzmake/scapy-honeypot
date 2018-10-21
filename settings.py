# coding: utf-8

import os

from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

IP_ADDRESS = os.getenv("IP_ADDRESS")
SSH_PORT = int(os.getenv("SSH_PORT"))
