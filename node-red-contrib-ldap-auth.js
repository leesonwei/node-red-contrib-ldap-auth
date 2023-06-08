/**
 * Copyright 2015 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

const { render } = require ("mustache");
const { createClient } = require ( "ldapjs");

var filterTemplate = '';
var ldap_bind_dn = null;
var ldap_bind_pw = null;

var anon_read = false;

var options = {
};

var searchOpts = {
	scope: 'sub',
	sizeLimit: 1
};

module.exports = {
	setup: function(args){
		options.url = args.uri;
		searchOpts.base = args.base;
		filterTemplate = args.filterTemplate;
		if (args.bind_dn) {
			ldap_bind_dn = args.bind_dn;
			ldap_bind_pw = args.bind_pw;
		}
		if (args.no_verify_ssl) {
			options.tlsOptions = {
				'rejectUnauthorized': false,
			};
		}
		if (args.anon_read) {
			anon_read = args.anon_read;
		}
		return this;
	},
	type: "credentials",
	users: function(username1) {
		return new Promise(function(resolve) {
			var ldap = createClient(options);
			ldap.on('error', err => {
				console.error(err);
				resolve(null);
			});
			var fn = function (err) {
				if (err) {
					resolve(null);
					ldap.unbind();
				}
				var temp = {};
				temp.username = username1;
				searchOpts.filter = render(filterTemplate, temp);
				ldap.search(searchOpts.base, searchOpts, function (err, res) {
					var found = false;
					if (err) {
						console.log(err);
						resolve(null);
						ldap.unbind();
					} else {
						res.on('searchEntry', function (entry) {
							found = true;
							resolve({ username: username1, permissions: "*" });
							ldap.unbind();
						});
						res.on('end', function (status) {
							if (!found) {
								resolve(null);
								ldap.unbind();
							}
						});
					}
				});
			};
			if (ldap_bind_dn) {
				ldap.bind(ldap_bind_dn, ldap_bind_pw, fn);
			}
			else {
				fn(null);
			}
		});
	},
	authenticate: function(username1,password) {
		return new Promise(function(resolve) {
			
			var ldap = createClient(options);
			
			ldap.on('error', err => {
				console.error(err);
				resolve(null);
			});
			var fn = function (err) {
				if (err) {
					resolve(null);
					ldap.unbind();
				}
				var temp = {};
				temp.username = username1;
				searchOpts.filter = render(filterTemplate, temp);
			
				ldap.search(searchOpts.base, searchOpts, function (err, res) {
					var found = false;
					if (err) {
						console.log(err);
						resolve(null);
						ldap.unbind();
					} else {
						res.on('searchEntry', function (entry) {
							found = true;
							console.log("found Users: " + entry.pojo);
							ldap.bind(entry.dn, password, function (err) {
								if (!err) {
									resolve({ username: username1, permissions: "*" });
									ldap.unbind();
								} else {
									resolve(null);
									ldap.unbind();
								}
							});
						});
						res.on('end', function (status) {
							if (!found) {
								resolve(null);
								ldap.unbind();
							}
						});
					}
				});
			};
			if (ldap_bind_dn) {
				ldap.bind(ldap_bind_dn, ldap_bind_pw, fn);
			}
			else {
				fn(null);
			}
		});
	},
	default: function() {
		return new Promise(function(resolve) {
			// Resolve with the user object for the default user.
			// If no default user exists, resolve with null.
			//resolve({anonymous: true, permissions:"read"});
			if (anon_read) {
				resolve({ anonymous: true, permissions: "read" });
			} else {
				resolve(null);
			}
		});
	}
 }

