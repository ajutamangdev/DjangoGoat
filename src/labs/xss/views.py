from django.shortcuts import render
from django.http import HttpResponse
import mimetypes
import re
import html

def detect_xss_patterns(content):
    """
    Check if content contains XSS patterns.
    Returns True if patterns found, False otherwise.
    """
    if not content or not isinstance(content, str):
        return False
    
    content_lower = content.lower()
    
    # XSS pattern list
    xss_patterns = [
        # Script tags
        r'<script[\s\S]*?>',
        r'</script>',
        r'<script[\s\S]*?/>',
        
        # Event handlers
        r'on\w+\s*=',
        r'onabort\s*=', r'onblur\s*=', r'onchange\s*=', r'onclick\s*=',
        r'ondblclick\s*=', r'onerror\s*=', r'onfocus\s*=', r'onkeydown\s*=',
        r'onkeypress\s*=', r'onkeyup\s*=', r'onload\s*=', r'onmousedown\s*=',
        r'onmousemove\s*=', r'onmouseout\s*=', r'onmouseover\s*=', r'onmouseup\s*=',
        r'onreset\s*=', r'onresize\s*=', r'onselect\s*=', r'onsubmit\s*=',
        r'onunload\s*=', r'oncontextmenu\s*=', r'ondrag\s*=', r'ondrop\s*=',
        
        # JavaScript URLs
        r'javascript\s*:',
        r'vbscript\s*:',
        r'data\s*:\s*text/html',
        r'data\s*:\s*application/javascript',
        
        # Dangerous HTML tags
        r'<iframe[\s\S]*?>',
        r'<object[\s\S]*?>',
        r'<embed[\s\S]*?>',
        r'<applet[\s\S]*?>',
        r'<meta[\s\S]*?>',
        r'<link[\s\S]*?>',
        r'<style[\s\S]*?>',
        r'<base[\s\S]*?>',
        
        # Image with event handlers
        r'<img[\s\S]*?on\w+[\s\S]*?>',
        r'<svg[\s\S]*?on\w+[\s\S]*?>',
        
        # Form elements with events
        r'<input[\s\S]*?on\w+[\s\S]*?>',
        r'<button[\s\S]*?on\w+[\s\S]*?>',
        r'<textarea[\s\S]*?on\w+[\s\S]*?>',
        r'<select[\s\S]*?on\w+[\s\S]*?>',
        
        # JavaScript functions
        r'alert\s*\(',
        r'confirm\s*\(',
        r'prompt\s*\(',
        r'eval\s*\(',
        r'settimeout\s*\(',
        r'setinterval\s*\(',
        r'function\s*\(',
        
        # DOM manipulation
        r'document\.',
        r'window\.',
        r'location\.',
        r'\.innerhtml',
        r'\.outerhtml',
        r'\.write\s*\(',
        r'\.writeln\s*\(',
        
        # CSS expressions
        r'expression\s*\(',
        r'behavior\s*:',
        r'-moz-binding',
        r'@import',
        
        # Template injection patterns
        r'\{\{[\s\S]*?\}\}',
        r'\$\{[\s\S]*?\}',
        r'<%[\s\S]*?%>',
        
        # Encoded patterns
        r'&#x?\d+;',
        r'%3c%73%63%72%69%70%74',  # URL encoded <script
        r'&lt;script',
        r'&lt;img',
        r'\\u[0-9a-f]{4}',  # Unicode encoding
        
        # Data URIs
        r'data:[\w/]+;base64,',
        
        # XML/XHTML patterns
        r'<\?xml[\s\S]*?\?>',
        r'<!doctype[\s\S]*?>',
        r'<!\[cdata\[',
        
        # Common bypass attempts
        r'scr\w*ipt',  # Like "scr" + something + "ipt"
        r'java\w*script',  # Like "java" + something + "script"
        r'vb\w*script',
        
        # HTML5 specific
        r'<audio[\s\S]*?on\w+[\s\S]*?>',
        r'<video[\s\S]*?on\w+[\s\S]*?>',
        r'<canvas[\s\S]*?on\w+[\s\S]*?>',
        r'<details[\s\S]*?on\w+[\s\S]*?>',
        
        # Form action manipulation
        r'formaction\s*=',
        r'action\s*=\s*["\']javascript:',
        
        # CSS injection
        r'@media[\s\S]*?\{',
        r'@keyframes[\s\S]*?\{',
        
        # WebRTC and other modern APIs
        r'navigator\.',
        r'geolocation\.',
        r'webkitrtc',
        r'mozrtc',
    ]
    
    # Check each pattern
    for pattern in xss_patterns:
        if re.search(pattern, content_lower, re.IGNORECASE | re.MULTILINE):
            return True
    
    # Additional checks for common XSS vectors
    dangerous_strings = [
        'javascript:', 'vbscript:', 'data:text/html',
        'onload=', 'onerror=', 'onclick=', 'onmouseover=',
        'alert(', 'confirm(', 'prompt(', 'eval(',
        'document.cookie', 'document.write', 'window.location',
        'innerHTML', 'outerHTML', 'insertAdjacentHTML',
        'setTimeout', 'setInterval', 'Function(',
        'constructor', 'prototype', '__proto__',
        'expression(', 'behavior:', '-moz-binding',
        'import', 'url(', '@import',
        'script:', 'about:', 'chrome:', 'resource:',
        'moz-icon:', 'ms-its:', 'mk:', 'wyciwyg:',
        'jar:', 'view-source:', 'gopher:', 'finger:',
        'feed:', 'pcast:', 'webcal:', 'wyciwyg:',
    ]
    
    for dangerous in dangerous_strings:
        if dangerous in content_lower:
            return True
    
    return False

def dashboard(request):
    """
    View for the XSS labs dashboard page.
    Lists all available XSS labs with descriptions and difficulty levels.
    """
    labs = [
        {
            'name': 'Basic Reflected XSS',
            'url': 'reflected_basic',
            'difficulty': 'BEGINNER',
            'description': 'Learn the fundamentals of reflected XSS through form input.',
            'icon': 'arrow-right-left',
            'estimated_time': '10 minutes'
        },
        {
            'name': 'URL Parameter XSS',
            'url': 'url_parameter',
            'difficulty': 'BEGINNER',
            'description': 'Exploit XSS vulnerabilities through URL parameters.',
            'icon': 'link',
            'estimated_time': '10 minutes'
        },
        {
            'name': 'Form Input XSS',
            'url': 'form_input',
            'difficulty': 'BEGINNER',
            'description': 'Discover XSS in form input processing.',
            'icon': 'edit',
            'estimated_time': '10 minutes'
        },
        {
            'name': 'Basic Stored XSS',
            'url': 'stored_basic',
            'difficulty': 'BEGINNER',
            'description': 'Understand persistent XSS through database storage.',
            'icon': 'database',
            'estimated_time': '15 minutes'
        },
        {
            'name': 'Simple DOM XSS',
            'url': 'dom_basic',
            'difficulty': 'BEGINNER',
            'description': 'Learn client-side XSS through DOM manipulation.',
            'icon': 'code',
            'estimated_time': '15 minutes'
        },
        {
            'name': 'HTML Attribute XSS',
            'url': 'attribute',
            'difficulty': 'INTERMEDIATE',
            'description': 'Exploit XSS within HTML attribute contexts.',
            'icon': 'tag',
            'estimated_time': '20 minutes'
        },
        {
            'name': 'JavaScript Context XSS',
            'url': 'js_context',
            'difficulty': 'INTERMEDIATE',
            'description': 'Break out of JavaScript string contexts.',
            'icon': 'terminal',
            'estimated_time': '20 minutes'
        },
        {
            'name': 'SVG XSS',
            'url': 'svg_xss',
            'difficulty': 'INTERMEDIATE',
            'description': 'Exploit XSS through SVG file handling.',
            'icon': 'image',
            'estimated_time': '20 minutes'
        },
        {
            'name': 'Markdown XSS',
            'url': 'markdown_xss',
            'difficulty': 'INTERMEDIATE',
            'description': 'Attack through vulnerable Markdown parsing.',
            'icon': 'file-text',
            'estimated_time': '25 minutes'
        },
        {
            'name': 'AJAX/JSON XSS',
            'url': 'ajax_json',
            'difficulty': 'INTERMEDIATE',
            'description': 'Exploit XSS in AJAX responses and JSON handling.',
            'icon': 'refresh-cw',
            'estimated_time': '25 minutes'
        },
        {
            'name': 'Filter Bypass XSS',
            'url': 'filter_bypass',
            'difficulty': 'ADVANCED',
            'description': 'Bypass common XSS protection mechanisms.',
            'icon': 'shield-off',
            'estimated_time': '30 minutes'
        },
        {
            'name': 'Content-Type XSS',
            'url': 'content_type',
            'difficulty': 'ADVANCED',
            'description': 'Exploit MIME type confusion vulnerabilities.',
            'icon': 'file-type',
            'estimated_time': '30 minutes'
        },
        {
            'name': 'Template Injection',
            'url': 'template',
            'difficulty': 'ADVANCED',
            'description': 'Advanced template injection attacks.',
            'icon': 'layout',
            'estimated_time': '35 minutes'
        },
        {
            'name': 'WebSocket XSS',
            'url': 'websocket_xss',
            'difficulty': 'ADVANCED',
            'description': 'Real-time XSS through WebSocket messages.',
            'icon': 'wifi',
            'estimated_time': '30 minutes'
        },
        {
            'name': 'File Upload XSS',
            'url': 'file_upload_xss',
            'difficulty': 'ADVANCED',
            'description': 'XSS through file upload functionality.',
            'icon': 'upload',
            'estimated_time': '25 minutes'
        }
    ]
    
    # Group labs by difficulty
    beginner_labs = [lab for lab in labs if lab['difficulty'] == 'BEGINNER']
    intermediate_labs = [lab for lab in labs if lab['difficulty'] == 'INTERMEDIATE']
    advanced_labs = [lab for lab in labs if lab['difficulty'] == 'ADVANCED']
    
    context = {
        'lab_title': 'XSS Labs Dashboard',
        'labs': labs,
        'beginner_labs': beginner_labs,
        'intermediate_labs': intermediate_labs,
        'advanced_labs': advanced_labs,
        'total_labs': len(labs),
        'estimated_total_time': sum([
            10 * len(beginner_labs),
            22 * len(intermediate_labs),
            30 * len(advanced_labs)
        ]) // len(labs) if labs else 0
    }
    
    return render(request, 'labs/xss/dashboard.html', context)

# XSS lab views
def reflected_basic(request):
    user_name = ""
    
    if request.method == 'POST':
        user_name = request.POST.get('name', '')
    elif request.GET.get('name'):
        user_name = request.GET.get('name', '')
    
    context = {
        'lab_title': 'Basic Reflected XSS',
        'difficulty': 'BEGINNER',
        'lab_description': 'Simple form that reflects user input without sanitization. Inject JavaScript that executes when displayed.',
        'next_lab_url': '/labs/xss/url-parameter/',
        'user_name': user_name,
        'hints': [
            {'title': 'Check Input Handling', 'content': 'User input inserted directly into HTML without filtering.'},
            {'title': 'HTML Tags Work', 'content': 'HTML tags in name field get rendered by browser.'},
            {'title': 'Need Execution', 'content': 'JavaScript must actually run - look for alert popup.'},
            {'title': 'Common Payloads', 'content': 'Try: <script>alert(1)</script>, <img src=x onerror=alert(1)>, <svg onload=alert(1)>'},
            {'title': 'Event Handlers', 'content': 'Use HTML event handlers like onerror, onload, onmouseover, onclick to trigger JavaScript execution.'},
            {'title': 'Solution', 'content': 'Enter: <script>alert(\'XSS Success!\')</script> and you should see a popup appear.'}
        ]
    }
    return render(request, 'labs/xss/reflected_basic.html', context)

def url_parameter(request):
    search_query = request.GET.get('search', '')
    
    context = {
        'lab_title': 'URL Parameter XSS',
        'difficulty': 'BEGINNER',
        'lab_description': 'URL parameters reflected in page content without sanitization.',
        'next_lab_url': '/labs/xss/form-input/',
        'search_query': search_query,
        'hints': [
            {'title': 'URL Parameters', 'content': 'Look at how URL parameters are processed and displayed on the page.'},
            {'title': 'Direct Injection', 'content': 'Try adding XSS payloads directly to the URL parameters.'},
            {'title': 'Execution Required', 'content': 'Success is only achieved when JavaScript executes and shows an alert popup.'},
            {'title': 'Common Payloads', 'content': 'Try: ?search=<script>alert(1)</script> or ?search=<img src=x onerror=alert(1)>'},
            {'title': 'Solution', 'content': 'Add ?search=<script>alert(\'XSS Success!\')</script> to the URL and see the popup.'}
        ]
    }
    return render(request, 'labs/xss/url_parameter.html', context)

def form_input(request):
    context = {
        'lab_title': 'Form Input XSS',
        'difficulty': 'BEGINNER',
        'lab_description': 'Form input processing without validation - multiple injection points.',
        'next_lab_url': '/labs/xss/stored-basic/',
        'hints': [
            {'title': 'Form Processing', 'content': 'Examine how form inputs are processed and displayed.'},
            {'title': 'Input Validation', 'content': 'Notice the lack of input validation on form fields.'},
            {'title': 'Solution', 'content': 'Enter <script>alert(\'XSS\')</script> in the form field.'}
        ]
    }
    return render(request, 'labs/xss/form_input.html', context)

def stored_basic(request):
    """
    View for the Basic Stored XSS lab.
    Handles comment submission and display.
    """
    from .models import Comment
    
    # Handle comment submission
    if request.method == 'POST':
        name = request.POST.get('name')
        comment_text = request.POST.get('comment')
        
        if name and comment_text:
            Comment.objects.create(name=name, comment=comment_text)
    
    # Get all comments to display
    comments = Comment.objects.all()
    
    context = {
        'lab_title': 'Basic Stored XSS',
        'difficulty': 'BEGINNER',
        'lab_description': 'Persistent XSS stored in database - payload executes for all visitors.',
        'next_lab_url': '/labs/xss/dom-basic/',
        'hints': [
            {'title': 'Persistent Storage', 'content': 'Payload stored in database - executes for every visitor.'},
            {'title': 'Multiple Fields', 'content': 'Both name and comment fields accept HTML input.'},
            {'title': 'Script Tags', 'content': 'Use <script> tags - stored and executed for all users.'},
            {'title': 'Solution', 'content': 'Enter the following in the comment field: <script>alert(\'XSS\')</script>'}
        ],
        'comments': comments
    }
    
    return render(request, 'labs/xss/stored_basic.html', context)

def dom_basic(request):
    context = {
        'lab_title': 'Simple DOM XSS',
        'difficulty': 'BEGINNER',
        'lab_description': 'Client-side XSS through DOM manipulation - vulnerability in JavaScript code.',
        'next_lab_url': '/labs/xss/attribute/',
        'hints': [
            {'title': 'Client-Side Vulnerability', 'content': 'JavaScript processes URL color parameter directly.'},
            {'title': 'URL Parameter', 'content': 'Add ?color=red to URL - JavaScript uses parameter value.'},
            {'title': 'innerHTML Usage', 'content': 'Color parameter inserted via innerHTML - try HTML tags.'},
            {'title': 'Solution', 'content': 'Add this to the URL: ?color=<script>alert(\'XSS\')</script>'}
        ]
    }
    return render(request, 'labs/xss/dom_basic.html', context)

def attribute(request):
    context = {
        'lab_title': 'HTML Attribute XSS',
        'difficulty': 'INTERMEDIATE',
        'lab_description': 'XSS in HTML attributes - break out of attribute context to inject event handlers.',
        'next_lab_url': '/labs/xss/js-context/',
        'hints': [
            {'title': 'Attribute Context', 'content': 'Input placed in HTML attributes (title, alt) - check generated HTML.'},
            {'title': 'Quote Escape', 'content': 'Close attribute quote, then add new attributes.'},
            {'title': 'Event Handlers', 'content': 'Add JavaScript events: onmouseover, onclick, onfocus.'},
            {'title': 'Solution', 'content': 'Enter this in the title field: " onmouseover="alert(\'XSS\') - Then hover over the image to trigger the alert.'}
        ],
        'success_message': 'You successfully executed an HTML attribute XSS attack!'
    }
    return render(request, 'labs/xss/attribute.html', context)

def js_context(request):
    context = {
        'lab_title': 'JavaScript Context XSS',
        'difficulty': 'INTERMEDIATE',
        'lab_description': 'XSS in JavaScript context - break out of string literals to execute code.',
        'next_lab_url': '/labs/xss/svg-xss/',
        'hints': [
            {'title': 'JavaScript Variables', 'content': 'Input embedded in JavaScript variables - check page source.'},
            {'title': 'String Escape', 'content': 'Close string quotes first, then add code.'},
            {'title': 'Comment Trick', 'content': 'Use // to comment out remaining code and prevent errors.'},
            {'title': 'Solution', 'content': 'Enter this in the username or status field: "; alert(\'XSS\'); // - Then click "Show User Info" to trigger the JavaScript.'}
        ],
        'success_message': 'You successfully executed a JavaScript context XSS attack!'
    }
    return render(request, 'labs/xss/js_context.html', context)

def svg_xss(request):
    context = {
        'lab_title': 'SVG XSS',
        'difficulty': 'INTERMEDIATE',
        'lab_description': 'SVG files with embedded JavaScript - XSS through vector graphics.',
        'next_lab_url': '/labs/xss/markdown-xss/',
        'hints': [
            {'title': 'SVG Events', 'content': 'SVG elements support onload, onclick, onmouseover events.'},
            {'title': 'SVG Scripts', 'content': 'SVG supports <script> tags that execute JavaScript.'},
            {'title': 'Animation Events', 'content': 'SVG animations can trigger events with <animate>.'},
            {'title': 'Solution', 'content': 'Try: <svg onload="alert(\'XSS\')"><rect width="100" height="100"/></svg>'}
        ],
        'success_message': 'You successfully executed an SVG XSS attack!'
    }
    return render(request, 'labs/xss/svg_xss.html', context)

def markdown_xss(request):
    """
    View for the Markdown XSS lab.
    Demonstrates XSS through markdown parsing vulnerabilities.
    """
    markdown_content = ""
    if request.method == 'POST':
        markdown_content = request.POST.get('markdown', '')
        # Basic markdown-like processing (intentionally vulnerable)
        # Convert **text** to <strong>text</strong>
        import re
        markdown_content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', markdown_content)
        # Convert [text](url) to <a href="url">text</a> - vulnerable to javascript: URLs
        markdown_content = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2">\1</a>', markdown_content)
    
    context = {
        'lab_title': 'Markdown XSS',
        'difficulty': 'INTERMEDIATE',
        'lab_description': 'Markdown parser with XSS vulnerabilities - raw HTML and JavaScript URLs allowed.',
        'next_lab_url': '/labs/xss/websocket-xss/',
        'hints': [
            {'title': 'Markdown Links', 'content': 'Markdown link syntax [text](url) can be exploited with javascript: URLs.'},
            {'title': 'HTML in Markdown', 'content': 'Many markdown parsers allow raw HTML, which can be exploited for XSS.'},
            {'title': 'JavaScript URLs', 'content': 'Try using javascript: protocol in markdown links.'},
            {'title': 'Solution', 'content': 'Try: [Click me](javascript:alert(\'XSS\'))'}
        ],
        'markdown_content': markdown_content,
        'success_message': 'You successfully executed a Markdown XSS attack!'
    }
    return render(request, 'labs/xss/markdown_xss.html', context)
    
    return render(request, 'labs/xss/markdown_xss.html', context)

def websocket_xss(request):
    """
    View for the WebSocket XSS lab.
    Demonstrates XSS through WebSocket message handling.
    """
    context = {
        'lab_title': 'WebSocket XSS',
        'difficulty': 'ADVANCED',
        'lab_description': 'Real-time XSS through WebSocket messages - client-side processing without sanitization.',
        'next_lab_url': None,
        'hints': [
            {'title': 'WebSocket Messages', 'content': 'WebSocket messages can contain user data that gets processed by JavaScript.'},
            {'title': 'Message Handling', 'content': 'Look at how incoming WebSocket messages are processed and displayed.'},
            {'title': 'Real-time XSS', 'content': 'XSS through WebSockets can affect multiple users in real-time.'},
            {'title': 'Solution', 'content': 'Send a message containing: <script>alert(\'XSS\')</script>'}
        ],
        'success_message': 'You successfully executed a WebSocket XSS attack!'
    }
    return render(request, 'labs/xss/websocket_xss.html', context)

def content_type(request):
    """
    View for the Content-Type XSS lab.
    Demonstrates vulnerabilities related to improper Content-Type handling.
    """
    
    # Handle direct file serving
    if request.GET.get('direct') == '1' and request.GET.get('content'):
        content = request.GET.get('content', '')
        filename = request.GET.get('filename', 'untitled')
        
        # Vulnerable: Determining Content-Type by file extension only
        content_type, _ = mimetypes.guess_type(filename)
        if not content_type:
            content_type = 'text/plain'
        
        response = HttpResponse(content, content_type=content_type)
        response['Content-Disposition'] = f'inline; filename="{filename}"'
        return response
    
    # Detect content type for preview
    detected_content_type = 'text/plain'
    if request.GET.get('filename'):
        filename = request.GET.get('filename')
        content_type, _ = mimetypes.guess_type(filename)
        if content_type:
            detected_content_type = content_type
    
    context = {
        'lab_title': 'Content-Type XSS',
        'difficulty': 'ADVANCED',
        'lab_description': 'MIME type confusion - browsers interpret content based on Content-Type headers.',
        'next_lab_url': None,
        'hints': [
            {'title': 'MIME Type Confusion', 'content': 'Browsers interpret content based on Content-Type headers.'},
            {'title': 'File Extension Spoofing', 'content': 'Try using different file extensions to change content type.'},
            {'title': 'HTML Content Type', 'content': 'Getting HTML content type allows script execution.'},
            {'title': 'Solution', 'content': 'Upload content with .html extension containing script tags.'}
        ],
        'detected_content_type': detected_content_type,
        'success_message': 'You successfully executed a Content-Type XSS attack!'
    }
    
    return render(request, 'labs/xss/content_type.html', context)

def ajax_json(request):
    context = {
        'lab_title': 'AJAX/JSON XSS',
        'difficulty': 'INTERMEDIATE',
        'lab_description': 'AJAX responses with user data processed by innerHTML - client-side XSS vulnerability.',
        'next_lab_url': '/labs/xss/filter-bypass/',
        'hints': [
            {'title': 'JSON Response', 'content': 'Look at the JavaScript code below. The search query is reflected in the JSON response.'},
            {'title': 'innerHTML Usage', 'content': 'The client-side code uses innerHTML to display the search results, which can execute HTML/JavaScript.'},
            {'title': 'Solution', 'content': 'Try searching for: <img src=x onerror=alert(\'XSS\')>'}
        ],
        'success_message': 'You successfully executed an AJAX/JSON XSS attack!'
    }
    return render(request, 'labs/xss/ajax_json.html', context)

def filter_bypass(request):
    """
    View for the Filter Bypass XSS lab.
    Implements basic XSS filters that can be bypassed.
    """
    filtered_comment = ""
    blocked_patterns = []
    
    if request.method == 'POST' and request.POST.get('comment'):
        comment = request.POST.get('comment')
        filtered_comment = comment
        
        # Basic XSS filters (intentionally bypassable)
        filters = [
            ('<script>', ''),
            ('</script>', ''),
            ('javascript:', ''),
            ('onclick', ''),
            ('onload', ''),
            ('onerror', ''),
            ('alert()', ''),
            ('eval()', ''),
            ('document.cookie', ''),
        ]
        
        for pattern, replacement in filters:
            if pattern in filtered_comment:
                blocked_patterns.append(pattern)
                filtered_comment = filtered_comment.replace(pattern, replacement)
    
    context = {
        'lab_title': 'Filter Bypass XSS',
        'difficulty': 'ADVANCED',
        'lab_description': 'Basic XSS filters with common bypass techniques - case sensitivity and alternative tags.',
        'next_lab_url': '/labs/xss/dom-clobbering/',
        'hints': [
            {'title': 'Case Sensitivity', 'content': 'Try different cases like <ScRiPt> instead of <script>.'},
            {'title': 'Alternative Tags', 'content': 'Use other HTML tags like <img>, <svg>, or <iframe> with event handlers.'},
            {'title': 'Encoding Bypass', 'content': 'Try URL encoding, HTML entities, or other encoding methods.'},
            {'title': 'Solution', 'content': 'Try: <img src=x onerror=alert(\'XSS\')> or <ScRiPt>alert(\'XSS\')</ScRiPt>'}
        ],
        'filtered_comment': filtered_comment,
        'blocked_patterns': blocked_patterns,
        'success_message': 'You successfully bypassed the XSS filters!'
    }
    
    return render(request, 'labs/xss/filter_bypass.html', context)

def file_upload_xss(request):
    """
    View for the File Upload XSS lab.
    Demonstrates XSS through file upload functionality.
    """
    uploaded_content = ""
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        try:
            uploaded_content = uploaded_file.read().decode('utf-8')
        except:
            uploaded_content = "Could not read file content"
    
    context = {
        'lab_title': 'File Upload XSS',
        'difficulty': 'ADVANCED',
        'lab_description': 'File upload with content display - uploaded files rendered as HTML without sanitization.',
        'next_lab_url': None,  # Last lab in the series
        'uploaded_content': uploaded_content,
        'hints': [
            {'title': 'File Content Processing', 'content': 'Uploaded files are read and their content is displayed directly on the page without any sanitization or filtering.'},
            {'title': 'HTML File Upload', 'content': 'Try uploading an HTML file containing JavaScript code. The file content will be rendered as HTML in the browser.'},
            {'title': 'Script Execution Context', 'content': 'When the file content is displayed using innerHTML, any JavaScript within it will execute in the current page context.'},
            {'title': 'File Types', 'content': 'You can upload files with extensions like .html, .txt, or even .js - the content is what matters, not the extension.'},
            {'title': 'Solution', 'content': 'Create a file with content: <script>alert(\'File Upload XSS!\')</script> and upload it. The script will execute when the content is displayed.'}
        ],
        'success_message': 'You successfully executed a File Upload XSS attack!'
    }
    return render(request, 'labs/xss/file_upload_xss.html', context)
