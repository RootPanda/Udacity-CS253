#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import re
import os
import jinja2
import random
import string
import hashlib
import json
import time
import logging

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(webapp2.RequestHandler):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    
    def validate_password(self, original_password):
        return self.PASS_RE.match(original_password)

    def verify_password(self, original_password, original_verify):
        return original_password == original_verify

    def validate_username(self, username):
        return self.USER_RE.match(username)

    def validate_email(self, email):
        return self.EMAIL_RE.match(email)
            
    def write_form(self, username="", email="",
                   error_username="", error_password="",
                   error_verify="", error_email=""):
        self.response.write(form % {"username": username, "email": email,
                                    "error_username": error_username,
                                    "error_password": error_password,
                                    "error_verify": error_verify,
                                    "error_email": error_email})
    
    def get(self):
        self.write_form()

    def post(self):
        original_username = self.request.get("username")
        original_password = self.request.get("password")
        original_verify = self.request.get("verify")
        original_email = self.request.get("email")
        
        invalidusername = True
        invalidpassword = True
        invalidverify = True
        invalidemail = True
        
        errormessage1 = ""
        errormessage2 = ""
        errormessage3 = ""
        errormessage4 = ""
        
        if not self.validate_username(original_username):
            invalidusername = False
            errormessage1 = "Invalid Username"
            
        if not self.validate_password(original_password):
            invalidpassword = False
            errormessage2 = "Invalid Password"
        elif not self.verify_password(original_password, original_verify):
            invalidverify = False
            errormessage3 = "Password...no match"

        if original_email and not self.validate_email(original_email):
            invalidemail = False
            errormessage4 = "Invalid Email"
        
        if invalidusername and invalidpassword and invalidverify and invalidemail:
            self.redirect('/blog/Welcome?username=%(username)s' % {"username": original_username})
        else:
            self.write_form(original_username, original_email, errormessage1, errormessage2, errormessage3, errormessage4)
        
class SuccessHandler(webapp2.RequestHandler):
    def get(self):
        username = self.request.get("username")
        self.response.write(formsuccess % {"username": username})

class Blog(db.Model):
    subject = db.StringProperty(required = True)
    blogtext = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class MainPage(Handler):
    def get(self):
        #blog = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        blog = self.bloglist()[0]
        age = self.bloglist()[1]
        self.render("blog.html", blog=blog, age=age)

    def bloglist(self, update = False):
        age = 0
        queryTime = 0
        key = "blog"
        blogs = memcache.get(key)
        if (blogs is None) or update:
            logging.error("test")
            blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
            blogs = list(blogs)
            memcache.set(key, blogs)
            memcache.set('time', time.time())
            age = 0
        else: 
            queryTime = memcache.get('time')
            age = time.time() - queryTime
        return blogs, age

class BlogPostPage(Handler):
    def get(self, blog_id):
        # blog = Blog.get_by_id(int(blog_id))
        # blog = [blog] # Single list item
        blog = self.blogitem(blog_id)[0]
        age = self.blogitem(blog_id)[1]
        
        if (blog):
            self.render("blog.html", blog=blog, age=age)
        else:
            self.error(404)
            self.response.out.write('Error 404.')

    def blogitem(self, blog_id, update = False):
        age = 0
        queryTime = 0.0
        key = str(blog_id)
        key_time = str(blog_id) + 'time'
        logging.error(key_time)
        blogs = memcache.get(key)
        if (blogs is None) or update:
            logging.error("test")
            blogs = Blog.get_by_id(int(blog_id))
            blogs = [blogs] # Single list item
            memcache.set(key, blogs)
            memcache.set(key_time, time.time())
        else: 
            queryTime = memcache.get(key_time)
            age = time.time() - queryTime
        return blogs, age

class NewPost(Handler):
    def render_newpost(self, subject="", blogtext="", error=""):
        self.render("newpost.html", subject=subject, blogtext=blogtext, error=error)
        
    def get(self):
        self.render_newpost()

    def post(self):
        subject = self.request.get("subject")
        blogtext = self.request.get("content")
	
	if subject and blogtext:
	    b = Blog(subject = subject, blogtext = blogtext)
	    b.put()
	    memcache.set("blog", None)     # reset cache
	    redirect_id = str(b.key().id())
	    self.redirect('/blog/%s' % redirect_id)
	else:
            error = "We need both a subject and blog text."
            self.render_newpost(subject, blogtext, error)

class SignupHandler(Handler):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    
    def validate_password(self, original_password):
        return self.PASS_RE.match(original_password)

    def verify_password(self, original_password, original_verify):
        return original_password == original_verify

    def validate_username(self, username):
        return self.USER_RE.match(username)

    def validate_email(self, email):
        return self.EMAIL_RE.match(email)
            
    

    def render_newpost(self, username="", email="",
                   error_username="", error_password="",
                   error_verify="", error_email=""):
        self.render("signup.html", username=username, email=email,
                    error_username=error_username, error_password=error_password,
                    error_verify=error_verify, error_email=error_email)

    def get(self):
        self.render_newpost()

    def post(self):
        original_username = self.request.get("username")
        original_password = self.request.get("password")
        original_verify = self.request.get("verify")
        original_email = self.request.get("email")
        
        invalidusername = True
        invalidpassword = True
        invalidverify = True
        invalidemail = True
        
        errormessage1 = ""
        errormessage2 = ""
        errormessage3 = ""
        errormessage4 = ""
        
        if not self.validate_username(original_username):
            invalidusername = False
            errormessage1 = "Invalid Username"
            
        if not self.validate_password(original_password):
            invalidpassword = False
            errormessage2 = "Invalid Password"
        elif not self.verify_password(original_password, original_verify):
            invalidverify = False
            errormessage3 = "Password...no match"

        if original_email and not self.validate_email(original_email):
            invalidemail = False
            errormessage4 = "Invalid Email"
        
        if invalidusername and invalidpassword and invalidverify and invalidemail:
            user_exist = db.GqlQuery("SELECT * FROM User WHERE username='%s'" % original_username)
            if user_exist.count():
                #print user_exist
                #self.redirect('/Error')
                errormessage1 = "User already exist"
                self.render_newpost(original_username, original_email, errormessage1, errormessage2, errormessage3, errormessage4)
                #self.response.write(user_exist)
            else:
                hash_password = self.make_pw_hash(original_username, original_password)
                user = User(username = original_username, password = hash_password,
                        email = original_email)
                user.put()
                self.response.headers.add_header('Set-Cookie', 'login_hash=%s; Path=/' % hash_password)
                self.redirect('/blog/Welcome')
        else:
            self.render_newpost(original_username, original_email, errormessage1, errormessage2, errormessage3, errormessage4)

    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5))

    def make_pw_hash(self, name, pw, salt=""):
        if (salt==""):
            salt = self.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s|%s' % (h, salt)

    

class SuccessHandler2(Handler):
    def get(self):
        hash_pass = self.request.cookies.get("login_hash")
        username = db.GqlQuery("SELECT * FROM User WHERE password='%s'" % hash_pass)

        if (username):
            self.render("signupsuccess.html", username=username.get().username)
            #self.render("signupsuccess.html", username=hash_pass)
        else:
            self.error(404)
            self.response.out.write('Error 404.')
        

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)

class LoginHandler(Handler):
    def render_newpost(self, error_message=""):
        self.render("login.html", error_message=error_message)

    def get(self):
        self.render_newpost()

    def valid_pw(self, name, pw, h):
        if (make_pw_hash(name, pw, h.split('|')[1]) == h):
            return True
        else:
            return False

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        user = db.GqlQuery("SELECT * FROM User WHERE password='%s'" % password)
        hash_pass = user.get().password

        if self.valid_pw(username, password, hash_pass):
            self.response.headers.add_header('Set-Cookie', 'login_hash=%s; Path=/' % hash_pass)
            self.redirect('/blog/Welcome')
        else:
            error_message = "Invalid Login"
            self.render_newpost(error_message)

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'login_hash=; Path=/')
        self.redirect('/blog/signup')

class FlushHandler(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')

class JsonHandler(Handler):
    def get(self):
        blog = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        blogList = blog.fetch(None)
        stringList = []
        for b in blogList:
            stringList.append({"content": b.blogtext, \
                               "created": str(b.created), \
                               "subject": b.subject})    
        outString = json.dumps(stringList)
        self.response.headers['Content-Type'] = "application/json; charset=UTF-8"
        self.response.out.write(outString)

class BlogPostJsonHandler(Handler):
    def get(self, blog_id):
        blog = Blog.get_by_id(int(blog_id))
        blog = [blog] # Single list item
        if (blog):
            stringList = []
            for b in blog:
                stringList.append({"content": b.blogtext, \
                                   "created": str(b.created), \
                                   "subject": b.subject})    
            outString = json.dumps(stringList)
            self.response.headers['Content-Type'] = "application/json; charset=UTF-8"
            self.response.out.write(outString)
        else:
            self.error(404)
            self.response.out.write('Error 404.')

app = webapp2.WSGIApplication([
                            ('/', MainHandler),
                            ('/blog/signup', SignupHandler),
                            ('/blog/Welcome', SuccessHandler2),
                            ('/blog/login', LoginHandler),
                            ('/blog/logout', LogoutHandler),
                            ('/blog/flush', FlushHandler),
                            ('/blog', MainPage),
                            ('/blog/newpost', NewPost),
                            ('/blog/([0-9]+)', BlogPostPage),
                            ('/blog/\.json', JsonHandler),
                            ('/blog/([0-9]+)\.json', BlogPostJsonHandler)
], debug=True)
