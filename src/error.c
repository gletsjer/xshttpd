#include	"config.h"

#include	<sys/types.h>
#include	<sys/stat.h>

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<pwd.h>

#include	"local.h"
#include	"setenv.h"
#include	"string.h"
#include	"path.h"

#ifndef		NOFORWARDS
extern	VOID	error			PROTO((const char *));
extern	VOID	redirect		PROTO((const char *, int));
extern	VOID	server_error		PROTO((const char *, const char *));
static	int	difference		PROTO((const char *, const char *));
static	int	check_user		PROTO((const struct passwd *));
static	VOID	user_unknown		PROTO((void));
static	VOID	post_on_non_cgi		PROTO((void));
static	VOID	invalid_path		PROTO((void));
static	VOID	dir_not_avail		PROTO((void));
static	VOID	not_regular		PROTO((void));
static	VOID	permission		PROTO((void));
static	VOID	not_found		PROTO((void));
static	VOID	no_relative_urls	PROTO((void));
static	VOID	bad_request		PROTO((void));
static	VOID	unknown_method		PROTO((void));
static	VOID	unauthorized		PROTO((void));
static	VOID	precondition_failed	PROTO((void));
static	VOID	local_no_page		PROTO((void));
static	VOID	local_invalid_link	PROTO((void));
static	VOID	local_no_pay		PROTO((void));
#endif		/* NOFORWARDS */

typedef	struct
{
	char		username[32];
	int		rank;
} userinfo;

static	const	char	*error_code, *error_readable, *error_url,
			*error_url_escaped, *error_url_expanded,
			*local_mode_str;
static	char		buffer[BUFSIZ], *temp;
char			rootdir[XS_PATH_MAX];
int			localmode;

extern	VOID
error DECL1C(char *, what)
{
	secprintf("Content-type: text/html\r\n\r\n");
	secprintf("<HTML><HEAD><TITLE>500 Error occurred</TITLE></HEAD\n");
	secprintf("<BODY><H1>500 Error occurred</H1>\n");
	secprintf("The <TT>error</TT> utility encountered the following\n");
	secprintf("error: <B>%s</B></BODY></HTML>\n", what);
	exit(0);
}

extern	VOID
redirect DECL2C_(char *, redir, int, code)
{
	secprintf("[redirect() called - transform_user_dir() is broken]\n");
}

extern	VOID
server_error DECL2CC(char *, readable, char *, code)
{
	secprintf("[server_error() called - transform_user_dir() is broken]\n");
}

static	int
difference DECL2CC(char *, what1, char *, what2)
{
	int		rank;
	const	char	*search, *follow;
	char		ch;

	rank = 0;
	for (search = what1, follow = what2; (ch = *search); search++)
	{
		if (ch == *follow)
			rank--;
		else if (!strchr(what2, ch))
			rank += 5;
		else
			rank += 2;
		if (*follow)
			follow++;
	}
	rank += strlen(follow);
	if (rank < 0)
		rank = 0;
	return(rank);
}

static	int
check_user DECL1C(struct passwd *, userinfo)
{
	char		dirname[XS_PATH_MAX], *end;

	if (transform_user_dir(dirname, userinfo, 0))
		return(0);
	strcat(dirname, "/");
	end = dirname + strlen(dirname);
	strcpy(end, INDEX_HTML);
	if (!access(dirname, F_OK))
		return(1);
	strcpy(end, INDEX_HTML_2);
	if (!access(dirname, F_OK))
		return(1);
	return(0);
}

static	VOID
user_unknown DECL0
{
	userinfo		top[10];
	const	struct	passwd	*user;
	int			count, count2, rank, said;
	char			filename[XS_PATH_MAX];

	strcpy(buffer, error_url_escaped + 2);
	if ((temp = strchr(buffer, '/')))
		*temp = 0;
	secprintf("The user <B>%s</B> is unknown to this system.<P>\n", buffer);
	strcpy(buffer, error_url + 2);
	if ((temp = strchr(buffer, '/')))
		*(temp++) = 0;
	for (count = 0; count < 10; count++)
	{
		top[count].username[0] = 0;
		top[count].rank = 10000;
	}
	while ((user = getpwent()))
	{
		rank = difference(buffer, user->pw_name);
		count = 0;
		while ((count < 10) && (top[count].rank < rank))
			count++;
		if (count < 10)
		{
			if (!check_user(user))
				continue;
			for (count2 = 9; count2 > count; count2--)
				top[count2] = top[count2 - 1];
			top[count].rank = rank;
			strcpy(top[count].username, user->pw_name);
		}
	}
	said = 0;
	for (count = 0; (count < 10) && (top[count].rank <= 20); count++)
	{
		if (!said)
		{
			secprintf("There are a few usernames that look similar\n");
			secprintf("to what you typed. Perhaps you meant one of\n");
			secprintf("these users:\n<UL>\n");
			said = 1;
		}
		secprintf("<LI><A HREF=\"/%%7E%s/\">%s</A>\n",
			top[count].username, top[count].username);
	}
	if (said)
		secprintf("</UL>\n");
	else
	{
		secprintf("There are no usernames here that even look like\n");
		secprintf("what you typed...<P>\n");
	}
	secprintf("You may look at the <A HREF=\"/\">main index page</A>");
	ssecprintf(filename, "%s/users.html", HTTPD_DOCUMENT_ROOT);
	if (!access(calcpath(filename), F_OK))
		secprintf(" or the <A HREF=\"/users.html\">user list</A>\n");
	secprintf(".\n");
}

static	VOID
post_on_non_cgi DECL0
{
	secprintf("You or your browser has attempted to use the <B>POST</B>\n");
	secprintf("method on something that is not a CGI binary. <B>POST</B>\n");
	secprintf("may only be used on CGI binaries. You can try using the\n");
	secprintf("<B>GET</B> and/or <B>HEAD</B> methods instead.<P>\n");
	secprintf("<A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
invalid_path DECL0
{
	secprintf("You have asked for a URL that the server does not like.\n");
	secprintf("In particular, the server does not accept paths with\n");
	secprintf("<B>..</B> in them. Please retry using another URL.<P>\n");
	secprintf("<A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
not_found DECL0
{
	char		prefix[BUFSIZ], base[XS_PATH_MAX], filename[XS_PATH_MAX];
	const	char	*begin, *match;
	int		len;
	struct	stat	statbuf;

	secprintf("The file <B>%s</B> does not exist on this server.\n",
		error_url_escaped);
	if (error_url[1] == '~')
	{
		match = error_url + 2;
		while (*match && (*match != '/'))
			match++;
		begin = match;
		strcpy(prefix, error_url);
		prefix[match - error_url] = 0;
		strcpy(base, error_url_expanded);
		base[(strlen(error_url_expanded) - strlen(error_url) +
			(match - error_url))] = 0;
		strcat(base, "/");
	} else
	{
		prefix[0] = 0;
		ssecprintf(base, "%s/%s/", HTTPD_ROOT, HTTPD_DOCUMENT_ROOT);
		begin = error_url;
	}

	len = strlen(begin);
	while (len >= 0)
	{
		ssecprintf(buffer, "%s%*.*s", base, -len, len, begin);
		if (!stat(buffer, &statbuf))
		{
			if (S_ISREG(statbuf.st_mode))
			{
				ssecprintf(buffer, "%s%*.*s", prefix,
					-len, len, begin);
				break;
			}
			if (!(S_ISDIR(statbuf.st_mode)))
			{
				len--;
				continue;
			}
			ssecprintf(buffer, "%s%*.*s%s%s", base, -len, len, begin,
				(begin[len-1] == '/') ? "" : "/", INDEX_HTML);
			if (!stat(buffer, &statbuf) && S_ISREG(statbuf.st_mode))
			{
				ssecprintf(buffer, "%s%*.*s%s", prefix,
					-len, len, begin,
					(begin[len - 1] == '/') ? "" : "/");
				break;
			}
			ssecprintf(buffer, "%s%*.*s%s%s", base, -len, len, begin,
				(begin[len-1] == '/') ? "" : "/", INDEX_HTML_2);
			if (!stat(buffer, &statbuf) && S_ISREG(statbuf.st_mode))
			{
				ssecprintf(buffer, "%s%*.*s%s", prefix,
					-len, len, begin,
					(begin[len - 1] == '/') ? "" : "/");
				break;
			}
		}
		len--;
	}
	if ((len >= 0) && strcmp(buffer, error_url) && strcmp(buffer, "/"))
	{
		secprintf("The path does seem to partially exist.\n");
		secprintf("Perhaps the path <A HREF=\"%s\">%s</A> will help.\n",
			buffer, buffer);
		secprintf("<P>Alternatively, y");
	} else
		secprintf("Y");
	secprintf("ou may take a look at <A HREF=\"/\">the main index</A>");
	ssecprintf(filename, "%s/users.html", HTTPD_DOCUMENT_ROOT);
	if (!access(calcpath(filename), F_OK))
		secprintf(" or the <A HREF=\"/users.html\">user list</A>\n");
	secprintf(".\n");
}

static	VOID
not_regular DECL0
{
	secprintf("What you requested is neither a directory nor a file.\n");
	secprintf("This error should never occur. Please notify the\n");
	secprintf("system administration of this machine.\n");
}

static	VOID
permission DECL0
{
	secprintf("The file <B>%s</B>, which you tried to retrieve from\n",
		error_url_escaped);
	secprintf("this server, is protected. You are not allowed to\n");
	secprintf("retrieve it. If this seems to be in error, please\n");
	secprintf("contact the person that created the file.\n");
	secprintf("<P><A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
dir_not_avail DECL0
{
	secprintf("The directory in which the file <B>%s</B> is located\n",
		error_url_escaped);
	secprintf("is currently not available for retrieval. Perhaps you\n");
	secprintf("can try later.\n");
	secprintf("<P><A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
no_relative_urls DECL0
{
	secprintf("Your browser has made a <EM>relative</EM> request to\n");
	secprintf("this server. This server, however, does not support\n");
	secprintf("relative URLs.\n");
	secprintf("<P><A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
bad_request DECL0
{
	const	char	*env;

	env = getenv("SERVER_PROTOCOL");
	secprintf("Your browser has made a <EM>%s</EM> request to\n", env);
	secprintf("this server, which is not valid according to the specification.\n");
	secprintf("The server can not possibly give you a sensible answer.\n");
	secprintf("<P><A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
unknown_method DECL0
{
	const	char	*env;

	env = getenv("REQUEST_METHOD");
	secprintf("Your browser has used a retrieval method other than\n");
	secprintf("<B>GET</B>, <B>POST</B>, <B>HEAD</B> and <B>OPTIONS</B>.\n");
	secprintf("In fact it used the method <B>%s</B>,\n",
		env ? env : "(unknown)");
	secprintf("which this server does not understand.\n");
	secprintf("<P><A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
unauthorized DECL0
{
	secprintf("You have entered a usercode/password combination\n");
	secprintf("which is not valid for the URL that you have requested\n");
	secprintf("Please try again with another usercode and/or password.\n");
}

static	VOID
precondition_failed DECL0
{
	secprintf("You have asked for a certain precondition which is not met\n");
	secprintf("by the requested data. So this data will not be shown.\n");
}

static	VOID
local_no_page DECL0
{
	const	char	*env;
	char		filename[XS_PATH_MAX];

	strcpy(buffer, error_url_escaped + 2);
	if ((temp = strchr(buffer, '/')))
		*temp = 0;
	secprintf("The user <B>%s</B>, whom you specified in your URL,\n", buffer);
	secprintf("exists on this system, but has no home page.\n");
	if ((env = getenv("REMOTE_ADDR")) && !strncmp(env, "131.155.140.", 12))
	{
		secprintf("If you would like to start a home page,\n");
		secprintf("please mail to <A HREF=\"mailto:");
		secprintf("www@stack.nl\">");
		secprintf("www@stack.nl</A> for details.\n");
	}
	secprintf("<P>Perhaps you meant somebody else; in this case, please\n");
	secprintf("have a look at the <A HREF=\"/\">main index</A>");
	ssecprintf(filename, "%s/users.html", HTTPD_DOCUMENT_ROOT);
	if (!access(calcpath(filename), F_OK))
		secprintf(" or the <A HREF=\"/users.html\">user list</A>\n");
	secprintf(".\n");
}

static	VOID
local_invalid_link DECL0
{
	strcpy(buffer, error_url_escaped + 2);
	if ((temp = strchr(buffer, '/')))
		*temp = 0;
	secprintf("An error has been made in linking <B>/www/%s</B> to\n", buffer);
	secprintf("a correct location. Please contact\n");
	secprintf("<A HREF=\"mailto:www@stack.nl\">");
	secprintf("www@stack.nl</A>.\n");
	secprintf("The problem will then be corrected as soon as possible.\n");
}

static	VOID
local_no_pay DECL0
{
	char		filename[XS_PATH_MAX];

	strcpy(buffer, error_url_escaped + 2);
	if ((temp = strchr(buffer, '/')))
		*temp = 0;
	secprintf("The user <B>%s</B>, whom you specified in your URL,\n", buffer);
	secprintf("has not payed his/her member fee to our computer society\n");
	secprintf("this year. The pages will be online again once the author\n");
	secprintf("has decided that he/she wants to remain a member.\n");
	secprintf("<P>Return to the <A HREF=\"/\">main index</A>\n");
	secprintf("for more information about our society");
	ssecprintf(filename, "%s/users.html", HTTPD_DOCUMENT_ROOT);
	if (!access(calcpath(filename), F_OK))
		secprintf(" or the <A HREF=\"/users.html\">user list</A>\n");
	secprintf(".\n");
}

extern	int
main DECL2(int, argc, char **, argv)
{
	if (getenv("HTTPD_ROOT"))
		strcpy(rootdir, getenv("HTTPD_ROOT"));
	else
		strcpy(rootdir, HTTPD_ROOT);
	alarm(240);
	if (!(error_code = getenv("ERROR_CODE")) ||
		!(error_readable = getenv("ERROR_READABLE")) ||
		!(error_url = getenv("ERROR_URL")) ||
		!(error_url_expanded = getenv("ERROR_URL_EXPANDED")) ||
		!(error_url_escaped = getenv("ERROR_URL_ESCAPED")) ||
		!(local_mode_str = getenv("LOCALMODE")))
		error("Not called properly - the server must call me");
	localmode = atoi(local_mode_str);
	secprintf("Content-type: text/html\r\n");
	secprintf("Status: %s\r\n\r\n", error_readable);
	secprintf("<HTML><HEAD><TITLE>%s</TITLE></HEAD>", error_readable);
	secprintf("<BODY><H1>%s</H1>\n", error_readable);
	if (!strcmp(error_code, "USER_UNKNOWN"))
		user_unknown();
	else if (!strcmp(error_code, "POST_ON_NON_CGI"))
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
	else if (!strcmp(error_code, "LOCAL_NO_PAGE"))
		local_no_page();
	else if (!strcmp(error_code, "LOCAL_INVALID_LINK"))
		local_invalid_link();
	else if (!strcmp(error_code, "LOCAL_NO_PAY"))
		local_no_pay();
	secprintf("</BODY></HTML>\n");
	exit(0);
}
