#### Handle cookie hashing
def make_secure_val(val):
	return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split("|")[0]
	if secure_val == make_secure_val(val):
		return val

#### Remove '\n' form post and replace with '<br>'
def render_post(response, post):
	response.out.write("<b>" + post.subject + "</b><br>")
	response.out.write(post.content)

