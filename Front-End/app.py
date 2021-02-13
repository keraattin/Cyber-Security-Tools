#!/usr/bin/env python3

# Pages
##############################################################################
## Homepage
@app.route('/', methods=['GET'])
def home():
    return render_template('home.html', port=PORT)


## Error Page
@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404
##############################################################################


# Pages
##############################################################################
## Homepage
@app.route('/', methods=['GET'])
def home():
    return render_template('home.html', port=PORT)
##############################################################################