from django.urls import path
from . import views

app_name = "xss"

urlpatterns = [
    # Main dashboard
    path("", views.dashboard, name="dashboard"),
    # === BEGINNER LEVEL (Basic XSS Concepts) ===
    path("reflected-basic/", views.reflected_basic, name="reflected_basic"),
    path("url-parameter/", views.url_parameter, name="url_parameter"),
    path("form-input/", views.form_input, name="form_input"),
    path("stored-basic/", views.stored_basic, name="stored_basic"),
    path("dom-basic/", views.dom_basic, name="dom_basic"),
    # === INTERMEDIATE LEVEL (Context-Specific XSS) ===
    path("attribute/", views.attribute, name="attribute"),
    path("js-context/", views.js_context, name="js_context"),
    path("svg-xss/", views.svg_xss, name="svg_xss"),
    path("markdown-xss/", views.markdown_xss, name="markdown_xss"),
    path("ajax-json/", views.ajax_json, name="ajax_json"),
    # === ADVANCED LEVEL (Bypass Techniques & Complex Scenarios) ===
    path("filter-bypass/", views.filter_bypass, name="filter_bypass"),
    path("content-type/", views.content_type, name="content_type"),
    path("file-upload-xss/", views.file_upload_xss, name="file_upload_xss"),
    path("websocket-xss/", views.websocket_xss, name="websocket_xss"),
]
