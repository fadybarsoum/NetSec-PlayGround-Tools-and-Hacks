# locate Playground configuration

import os, sys
from playground.config import GlobalPlaygroundConfigData, extractList
PLAYGROUND_BASE_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
SRC_ROOT = os.path.abspath(os.path.join(PLAYGROUND_BASE_DIRECTORY, ".."))

GlobalPlaygroundConfigData.LoadPlaygroundConfig([os.getcwd(), SRC_ROOT, PLAYGROUND_BASE_DIRECTORY])
configData = GlobalPlaygroundConfigData.getConfig(__name__)
configData.setDefault("base_directory", PLAYGROUND_BASE_DIRECTORY)

prependedImports = extractList(GlobalPlaygroundConfigData.CONFIG_DATA, "playground.extra_import_paths.prepended_paths", "")
appendedImports = extractList(GlobalPlaygroundConfigData.CONFIG_DATA, "playground.extra_import_paths.appended_paths", "")

sys.path = prependedImports + sys.path + appendedImports

import playgroundlog
import network as network
import crypto

blah = network
