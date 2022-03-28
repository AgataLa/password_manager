#!/var/www/webApp/venv/bin/python
import sys
import os
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/webApp/")

from passkeeper import create_app
application = create_app()
