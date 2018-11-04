# coding: utf-8

import os

from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

TARGET_IP_ADDRESS = os.getenv("TARGET_IP_ADDRESS")

LOGGER = os.getenv("LOGGER")

FLUENT_HOST = os.getenv("FLUENT_HOST")
FLUENT_PORT = int(os.getenv("FLUENT_PORT"))
