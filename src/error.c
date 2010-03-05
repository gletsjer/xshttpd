/* Copyright (C) 1995, 1996 by Sven Berkvens (sven@stack.nl) */
/* Copyright (C) 1998-2008 by Johan van Selst (johans@stack.nl) */

#include	"config.h"

#include	<sys/types.h>
#include	<sys/stat.h>

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<string.h>
#include	<pwd.h>

#include	"path.h"
#include	"decode.h"

static	void	error			(const char *)	NORETURN;
static	void	user_unknown		(void);
static	void	post_on_non_cgi		(void);
static	void	invalid_path		(void);
static	void	dir_not_avail		(void);
static	void	not_regular		(void);
static	void	permission		(void);
static	void	not_found		(void);
static	void	no_relative_urls	(void);
static	void	bad_request		(void);
static	void	unknown_method		(void);
static	void	unauthorized		(void);
static	void	precondition_failed	(void);
static	void	not_acceptable		(void);
static	void	entity_too_large	(void);
static	void	local_no_page		(void);
static	void	local_invalid_link	(void);
static	void	local_no_pay		(void);

static	const	char	*error_code, *error_readable, *error_url,
			*error_url_escaped, *error_url_expanded;
static	char		buffer[BUFSIZ];

static void
error(const char *what)
{
	printf("Content-type: text/html\r\n\r\n");
	printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	printf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
		"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
	printf("<html xmlns=\"http://www.w3.org/1999/xhtml\">\n");
	printf("<head><title>500 Error occurred</title></head>\n");
	printf("<body><h1>500 Error occurred</h1>\n");
	printf("<p>The <tt>error</tt> utility encountered the following\n");
	printf("error: <b>%s</b></p></body></html>\n", what);
	exit(0);
}

static	void
user_unknown()
{
	int		len = 0;
	char		filename[XS_PATH_MAX], *temp;

	if ((temp = strchr(error_url_escaped + 2, '/')))
		len = temp - error_url_escaped - 2;
	printf("<p>The user <b>%*.*s</b> is unknown to this system.</p>\n",
		len, len, error_url_escaped + 2);
	printf("<p>You may look at the <a href=\"/\">main index page</a>");
	snprintf(filename, XS_PATH_MAX, "%s/users.html", HTML_DIR);
	if (!access(calcpath(filename), F_OK))
		printf(" or the <a href=\"/users.html\">user list</a>\n");
	printf(".</p>\n");
}

static	void
post_on_non_cgi()
{
	printf("<p>You or your browser has attempted to use the <b>POST</b>,\n");
	printf("<b>PUT</b> or <b>DELETE</b> method on something that is\n");
	printf("not a CGI binary.\n");
	printf("These operations may only be performed on CGI binaries.\n");
	printf("You should try using the <b>GET</b> and/or <b>HEAD</b>\n");
	printf("methods instead.</p>\n");

	printf("<p><a href=\"/\">Get out of here!</a></p>\n");
}

static	void
invalid_path()
{
	printf("<p>You have asked for a URL that the server does not like.\n");
	printf("In particular, the server does not accept paths with\n");
	printf("<b>..</b> in them. Please retry using another URL.</p>\n");
	printf("<p><a href=\"/\">Get out of here!</a></p>\n");
}

static	void
not_found()
{
	char		prefix[BUFSIZ], base[XS_PATH_MAX], filename[XS_PATH_MAX];
	const	char	*begin, *match;
	int		len;
	struct	stat	statbuf;

	printf("<p>The file <b>%s</b> does not exist on this server.</p>\n",
		error_url_escaped);
	if (error_url[1] == '~')
	{
		match = error_url + 2;
		while (*match && (*match != '/'))
			match++;
		begin = match;
		strlcpy(prefix, error_url, BUFSIZ);
		prefix[match - error_url] = 0;
		strlcpy(base, error_url_expanded, BUFSIZ);
		base[(strlen(error_url_expanded) - strlen(error_url) +
			(match - error_url))] = 0;
		strlcat(base, "/", XS_PATH_MAX);
	} else
	{
		prefix[0] = 0;
		strlcpy(base, calcpath(HTML_DIR), XS_PATH_MAX);
		begin = error_url;
	}

	len = strlen(begin);
	while (len >= 0)
	{
		snprintf(buffer, BUFSIZ, "%s%*.*s",
			base, -len, len, begin);
		if (!stat(buffer, &statbuf))
		{
			if (S_ISREG(statbuf.st_mode))
			{
				snprintf(buffer, BUFSIZ, "%s%*.*s",
					prefix, -len, len, begin);
				break;
			}
			if (!(S_ISDIR(statbuf.st_mode)))
			{
				len--;
				continue;
			}
			snprintf(buffer, BUFSIZ, "%s%*.*s%s%s",
				base, -len, len, begin,
				(begin[len-1] == '/') ? "" : "/", INDEX_HTML);
			if (!stat(buffer, &statbuf) && S_ISREG(statbuf.st_mode))
			{
				snprintf(buffer, BUFSIZ, "%s%*.*s%s",
					prefix, -len, len, begin,
					(begin[len - 1] == '/') ? "" : "/");
				break;
			}
		}
		len--;
	}
	if ((len >= 0) && strcmp(buffer, error_url) && strcmp(buffer, "/"))
	{
		char	*escurl = escape(buffer);

		printf("<p>The path does seem to partially exist.\n");
		printf("Perhaps the path <a href=\"%s\">%s</a> will\n",
			buffer, escurl);
		printf ("help.</p>\n<p>Alternatively, y");
		free(escurl);
	} else
		printf("<p>Y");
	printf("ou may take a look at <a href=\"/\">the main index</a>");
	snprintf(filename, XS_PATH_MAX, "%s/users.html", HTML_DIR);
	if (!access(calcpath(filename), F_OK))
		printf(" or the <a href=\"/users.html\">user list</a>\n");
	printf(".</p>\n");
}

static	void
not_regular()
{
	printf("<p>What you requested is neither a directory nor a file.\n");
	printf("This error should never occur. Please notify the\n");
	printf("system administration of this machine.</p>\n");
}

static	void
permission()
{
	printf("<p>The file <b>%s</b>, which you tried to retrieve from\n",
		error_url_escaped);
	printf("this server, is protected. You are not allowed to\n");
	printf("retrieve it. If this seems to be in error, please\n");
	printf("contact the person that created the file.</p>\n");
	printf("<p><a href=\"/\">Get out of here!</a></p>\n");
}

static	void
dir_not_avail()
{
	printf("<p>The directory in which the file <b>%s</b> is located\n",
		error_url_escaped);
	printf("is currently not available for retrieval. Perhaps you\n");
	printf("can try later.</p>\n");
	printf("<p><a href=\"/\">Get out of here!</a></p>\n");
}

static	void
no_relative_urls()
{
	printf("<p>Your browser has made a <em>relative</em> request to\n");
	printf("this server. This server, however, does not support\n");
	printf("relative URLs.</p>\n");
	printf("<p><a href=\"/\">Get out of here!</a></p>\n");
}

static	void
bad_request()
{
	const	char	*temp;

	temp = getenv("SERVER_PROTOCOL");
	printf("<p>Your browser has made a <em>%s</em> request to\n", temp);
	printf("this server, which is not valid according to the\n");
	printf ("specification. The server can not possibly give you a\n");
	printf ("sensible answer.</p>\n");
	printf("<p><a href=\"/\">Get out of here!</a></p>\n");
}

static	void
unknown_method()
{
	const	char	*temp;

	temp = getenv("REQUEST_METHOD");
	printf("<p>Your browser has used a retrieval method other than\n");
	printf("<b>GET</b>, <b>POST</b>, <b>HEAD</b> and <b>OPTIONS</b>.\n");
	printf("In fact it used the method <b>%s</b>,\n",
		temp ? temp : "(unknown)");
	printf("which this server does not understand.</p>\n");
	printf("<p><a href=\"/\">Get out of here!</a></p>\n");
}

static	void
unauthorized()
{
	printf("<p>You have entered a usercode/password combination\n");
	printf("which is not valid for the URL that you have requested\n");
	printf("Please try again with another usercode and/or password.</p>\n");
}

static	void
precondition_failed()
{
	printf("<p>You have asked for a certain precondition which is ");
	printf("not met by the requested data.\n");
	printf("So this data will not be shown.</p>\n");
}

static	void
not_acceptable()
{
	printf("<p>The requested data is not available in any of the ");
	printf("formats you deem acceptable.\n");
	printf("So this data will not be shown.</p>\n");
}

static	void
entity_too_large()
{
	printf("<p>The server is refusing to process a request because ");
	printf("the request entity is larger than the server ");
	printf("is willing or able to process.</p>\n");
}

static	void
local_no_page()
{
	char		filename[XS_PATH_MAX], *temp;

	strlcpy(buffer, error_url_escaped + 2, BUFSIZ);
	if ((temp = strchr(buffer, '/')))
		*temp = 0;
	printf("<p>The user <b>%s</b>, whom you specified in your URL,\n",
		buffer);
	printf("exists on this system, but has no home page.\n");
	if ((temp = getenv("REMOTE_ADDR")) && !strncmp(temp, "131.155.140.", 12))
	{
		printf("If you would like to start a home page,\n");
		printf("please mail to <a href=\"mailto:");
		printf("www@stack.nl\">");
		printf("www@stack.nl</a> for details.>");
	}
	printf("</p>\n");
	printf("<p>Perhaps you meant somebody else; in this case, please\n");
	printf("have a look at the <a href=\"/\">main index</a>");
	snprintf(filename, XS_PATH_MAX, "%s/users.html", HTML_DIR);
	if (!access(calcpath(filename), F_OK))
		printf(" or the <a href=\"/users.html\">user list</a>\n");
	printf(".</p>\n");
}

static	void
local_invalid_link()
{
	char		*temp;

	strlcpy(buffer, error_url_escaped + 2, BUFSIZ);
	if ((temp = strchr(buffer, '/')))
		*temp = 0;
	printf("<p>An error has been made in linking <b>/www/%s</b> to\n",
		buffer);
	printf("a correct location. Please contact\n");
	printf("<A HREF=\"mailto:www@stack.nl\">");
	printf("www@stack.nl</A>. The problem will then be corrected as\n");
	printf("soon as possible.</p>\n");
}

static	void
local_no_pay()
{
	char		filename[XS_PATH_MAX], *temp;

	strlcpy(buffer, error_url_escaped + 2, BUFSIZ);
	if ((temp = strchr(buffer, '/')))
		*temp = 0;
	printf("<p>The user <b>%s</b>, whom you specified in your URL,\n",
		buffer);
	printf("has not paid his/her member fee to our computer society\n");
	printf("this year. The pages will be online again once the author\n");
	printf("has decided that he/she wants to remain a member.</p>\n");
	printf("<p>Return to the <a href=\"/\">main index</a>\n");
	printf("for more information about our society");
	snprintf(filename, XS_PATH_MAX, "%s/users.html", HTML_DIR);
	if (!access(calcpath(filename), F_OK))
		printf(" or the <a href=\"/users.html\">user list</a>\n");
	printf(".</p>\n");
}

int
main(int argc, char **argv)
{
	alarm(240);
	if (!(error_code = getenv("ERROR_CODE")) ||
		!(error_readable = getenv("ERROR_READABLE")) ||
		!(error_url = getenv("ERROR_URL")) ||
		!(error_url_expanded = getenv("ERROR_URL_EXPANDED")) ||
		!(error_url_escaped = getenv("ERROR_URL_ESCAPED")))
		error("Not called properly - the server must call me");
	printf("Content-type: text/html\r\n");
	printf("Status: %s\r\n\r\n", error_readable);
	printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	printf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
		"\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n");
	printf("<html xmlns=\"http://www.w3.org/1999/xhtml\">\n");
	printf("<head><title>%s</title></head>\n", error_readable);
	printf("<body><h1>%s</h1>\n", error_readable);
	if (!strcmp(error_code, "USER_UNKNOWN"))
		user_unknown();
	else if (!strcmp(error_code, "METHOD_NOT_ALLOWED"))
		post_on_non_cgi();
	else if (!strcmp(error_code, "INVALID_PATH"))
		invalid_path();
	else if (!strcmp(error_code, "DIR_NOT_AVAIL"))
		dir_not_avail();
	else if (!strcmp(error_code, "NOT_REGULAR"))
		not_regular();
	else if (!strcmp(error_code, "PERMISSION"))
		permission();
	else if (!strcmp(error_code, "NOT_FOUND"))
		not_found();
	else if (!strcmp(error_code, "NO_RELATIVE_URLS"))
		no_relative_urls();
	else if (!strcmp(error_code, "BAD_REQUEST"))
		bad_request();
	else if (!strcmp(error_code, "UNKNOWN_METHOD"))
		unknown_method();
	else if (!strcmp(error_code, "UNAUTHORIZED"))
		unauthorized();
	else if (!strcmp(error_code, "PRECONDITION_FAILED"))
		precondition_failed();
	else if (!strcmp(error_code, "NOT_ACCEPTABLE"))
		not_acceptable();
	else if (!strcmp(error_code, "ENTITY_TOO_LARGE"))
		entity_too_large();
	else if (!strcmp(error_code, "LOCAL_NO_PAGE"))
		local_no_page();
	else if (!strcmp(error_code, "LOCAL_INVALID_LINK"))
		local_invalid_link();
	else if (!strcmp(error_code, "LOCAL_NO_PAY"))
		local_no_pay();
	printf("</body></html>\n");
	(void)argc;
	(void)argv;
	return 0;
}
