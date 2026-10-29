#!/bin/bash
S=/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad
for r in pallets/flask pallets/jinja psf/requests urllib3/urllib3 python-pillow/Pillow tornadoweb/tornado encode/starlette \
  fastapi/fastapi yaml/pyyaml paramiko/paramiko celery/celery mitmproxy/mitmproxy HumanSignal/label-studio \
  ParisNeo/lollms-webui benoitc/gunicorn Pylons/waitress bottlepy/bottle cherrypy/cherrypy Kludex/python-multipart \
  py-pdf/pypdf pyload/pyload OctoPrint/OctoPrint frappe/frappe wagtail/wagtail zulip/zulip indico/indico \
  Pylons/pyramid saleor/saleor netbox-community/netbox paperless-ngx/paperless-ngx vllm-project/vllm \
  langchain-ai/langchain open-webui/open-webui jupyter/notebook jupyter-server/jupyter_server bokeh/bokeh \
  streamlit/streamlit apache/superset mkdocs/mkdocs sphinx-doc/sphinx keras-team/keras horovod/horovod \
  pgadmin-org/pgadmin4 SickChill/sickchill Pyrogram/pyrogram plotly/dash; do
  d=$S/rw5/repos/${r/\//__}
  [ -d $d ] && continue
  timeout 900 git clone -q --filter=blob:none --no-checkout https://github.com/$r $d 2>>$S/rw5/clone.err && echo "ok $r" || echo "FAIL $r"
done
echo CLONE DONE
