#include	"config.h"

#include	<sys/types.h>
#include	<sys/stat.h>

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<pwd.h>

#include	"local.h"
#include	"setenv.h"
#include	"path.h"
#include	"mystring.h"

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
} userrank;

static	const	char	*error_code, *error_readable, *error_url,
			*error_url_escaped, *error_url_expanded,
			*local_mode_str;
static	char		buffer[BUFSIZ], *temp;
char			rootdir[XS_PATH_MAX];
int			localmode;

extern	VOID
error DECL1C(char *, what)
{
	printf("Content-type: text/html\r\n\r\n");
	printf("<HTML><HEAD><TITLE>500 Error occurred</TITLE></HEAD\n");
	printf("<BODY><H1>500 Error occurred</H1>\n");
	printf("The <TT>error</TT> utility encountered the following\n");
	printf("error: <B>%s</B></BODY></HTML>\n", what);
	exit(0);
}

extern	VOID
redirect DECL2C_(char *, redir, int, code)
{
	printf("[redirect() called - transform_user_dir() is broken]\n");
	(void)redir;
	(void)code;
}

extern	VOID
server_error DECL2CC(char *, readable, char *, code)
{
	printf("[server_error() called - transform_user_dir() is broken]\n");
	(void)readable;
	(void)code;
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
	userrank		top[10];
	const	struct	passwd	*user;
	int			count, count2, rank, said;
	char			filename[XS_PATH_MAX];

	strcpy(buffer, error_url_escaped + 2);
	if ((temp = strchr(buffer, '/')))
		*temp = 0;
	printf("The user <B>%s</B> is unknown to this system.<P>\n", buffer);
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
			printf("There are a few usernames that look similar\n");
			printf("to what you typed. Perhaps you meant one of\n");
			printf("these users:\n<UL>\n");
			said = 1;
		}
		printf("<LI><A HREF=\"/%%7E%s/\">%s</A>\n",
			top[count].username, top[count].username);
	}
	if (said)
		printf("</UL>\n");
	else
	{
		printf("There are no usernames here that even look like\n");
		printf("what you typed...<P>\n");
	}
	printf("You may look at the <A HREF=\"/\">main index page</A>");
	sprintf(filename, "%s/users.html", HTTPD_DOCUMENT_ROOT);
	if (!access(calcpath(filename), F_OK))
		printf(" or the <A HREF=\"/users.html\">user list</A>\n");
	printf(".\n");
}

static	VOID
post_on_non_cgi DECL0
{
	printf("You or your browser has attempted to use the <B>POST</B>\n");
	printf("method on something that is not a CGI binary. <B>POST</B>\n");
	printf("may only be used on CGI binaries. You can try using the\n");
	printf("<B>GET</B> and/or <B>HEAD</B> methods instead.<P>\n");
	printf("<A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
invalid_path DECL0
{
	printf("You have asked for a URL that the server does not like.\n");
	printf("In particular, the server does not accept paths with\n");
	printf("<B>..</B> in them. Please retry using another URL.<P>\n");
	printf("<A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
not_found DECL0
{
	char		prefix[BUFSIZ], base[XS_PATH_MAX], filename[XS_PATH_MAX];
	const	char	*begin, *match;
	int		len;
	struct	stat	statbuf;

	printf("The file <B>%s</B> does not exist on this server.\n",
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
		sprintf(base, "%s/%s/", HTTPD_ROOT, HTTPD_DOCUMENT_ROOT);
		begin = error_url;
	}

	len = strlen(begin);
	while (len >= 0)
	{
		sprintf(buffer, "%s%*.*s", base, -len, len, begin);
		if (!stat(buffer, &statbuf))
		{
			if (S_ISREG(statbuf.st_mode))
			{
				sprintf(buffer, "%s%*.*s", prefix,
					-len, len, begin);
				break;
			}
			if (!(S_ISDIR(statbuf.st_mode)))
			{
				len--;
				continue;
			}
			sprintf(buffer, "%s%*.*s%s%s", base, -len, len, begin,
				(begin[len-1] == '/') ? "" : "/", INDEX_HTML);
			if (!stat(buffer, &statbuf) && S_ISREG(statbuf.st_mode))
			{
				sprintf(buffer, "%s%*.*s%s", prefix,
					-len, len, begin,
					(begin[len - 1] == '/') ? "" : "/");
				break;
			}
			sprintf(buffer, "%s%*.*s%s%s", base, -len, len, begin,
				(begin[len-1] == '/') ? "" : "/", INDEX_HTML_2);
			if (!stat(buffer, &statbuf) && S_ISREG(statbuf.st_mode))
			{
				sprintf(buffer, "%s%*.*s%s", prefix,
					-len, len, begin,
					(begin[len - 1] == '/') ? "" : "/");
				break;
			}
		}
		len--;
	}
	if ((len >= 0) && strcmp(buffer, error_url) && strcmp(buffer, "/"))
	{
		printf("The path does seem to partially exist.\n");
		printf("Perhaps the path <A HREF=\"%s\">%s</A> will help.\n",
			buffer, buffer);
		printf("<P>Alternatively, y");
	} else
		printf("Y");
	printf("ou may take a look at <A HREF=\"/\">the main index</A>");
	sprintf(filename, "%s/users.html", HTTPD_DOCUMENT_ROOT);
	if (!access(calcpath(filename), F_OK))
		printf(" or the <A HREF=\"/users.html\">user list</A>\n");
	printf(".\n");
}

static	VOID
not_regular DECL0
{
	printf("What you requested is neither a directory nor a file.\n");
	printf("This error should never occur. Please notify the\n");
	printf("system administration of this machine.\n");
}

static	VOID
permission DECL0
{
	printf("The file <B>%s</B>, which you tried to retrieve from\n",
		error_url_escaped);
	printf("this server, is protected. You are not allowed to\n");
	printf("retrieve it. If this seems to be in error, please\n");
	printf("contact the person that created the file.\n");
	printf("<P><A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
dir_not_avail DECL0
{
	printf("The directory in which the file <B>%s</B> is located\n",
		error_url_escaped);
	printf("is currently not available for retrieval. Perhaps you\n");
	printf("can try later.\n");
	printf("<P><A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
no_relative_urls DECL0
{
	printf("Your browser has made a <EM>relative</EM> request to\n");
	printf("this server. This server, however, does not support\n");
	printf("relative URLs.\n");
	printf("<P><A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
bad_request DECL0
{
	const	char	*env;

	env = getenv("SERVER_PROTOCOL");
	printf("Your browser has made a <EM>%s</EM> request to\n", env);
	printf("this server, which is not valid according to the specification.\n");
	printf("The server can not possibly give you a sensible answer.\n");
	printf("<P><A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
unknown_method DECL0
{
	const	char	*env;

	env = getenv("REQUEST_METHOD");
	printf("Your browser has used a retrieval method other than\n");
	printf("<B>GET</B>, <B>POST</B>, <B>HEAD</B> and <B>OPTIONS</B>.\n");
	printf("In fact it used the method <B>%s</B>,\n",
		env ? env : "(unknown)");
	printf("which this server does not understand.\n");
	printf("<P><A HREF=\"/\">Get out of here!</A>\n");
}

static	VOID
unauthorized DECL0
{
	printf("You have entered a usercode/password combination\n");
	printf("which is not valid for the URL that you have requested\n");
	printf("Please try again with another usercode and/or password.\n");
}

static	VOID
precondition_failed DECL0
{
	printf("You have asked for a certain precondition which is not met\n");
	printf("by the requested data. So this data will not be shown.\n");
}

static	VOID
local_no_page DECL0
{
	const	char	*env;
	char		filename[XS_PATH_MAX];

	strcpy(buffer, error_url_escaped + 2);
	if ((temp = strchr(buffer, '/')))
		*temp = 0;
	printf("The user <B>%s</B>, whom you specified in your URL,\n", buffer);
	printf("exists on this system, but has no home page.\n");
	if ((env = getenv("REMOTE_ADDR")) && !strncmp(env, "131.155.140.", 12))
	{
		printf("If you would like to start a home page,\n");
		printf("please mail to <A HREF=\"mailto:");
		printf("www@stack.nl\">");
		printf("www@stack.nl</A> for details.\n");
	}
	printf("<P>Perhaps you meant somebody else; in this case, please\n");
	printf("have a look at the <A HREF=\"/\">main index</A>");
	sprintf(filename, "%s/users.html", HTTPD_DOCUMENT_ROOT);
	if (!access(calcpath(filename), F_OK))
		printf(" or the <A HREF=\"/users.html\">user list</A>\n");
	printf(".\n");
}

static	VOID
local_invalid_link DECL0
{
	strcpy(buffer, error_url_escaped + 2);
	if ((temp = strchr(buffer, '/')))
		*temp = 0;
	printf("An error has been made in linking <B>/www/%s</B> to\n", buffer);
	printf("a correct location. Please contact\n");
	printf("<A HREF=\"mailto:www@stack.nl\">");
	printf("www@stack.nl</A>.\n");
	printf("The problem will then be corrected as soon as possible.\n");
}

static	VOID
local_no_pay DECL0
{
	char		filename[XS_PATH_MAX];

	strcpy(buffer, error_url_escaped + 2);
	if ((temp = strchr(buffer, '/')))
		*temp = 0;
	printf("The user <B>%s</B>, whom you specified in your URL,\n", buffer);
	printf("has not paid his/her member fee to our computer society\n");
	printf("this year. The pages will be online again once the author\n");
	printf("has decided that he/she wants to remain a member.\n");
	printf("<P>Return to the <A HREF=\"/\">main index</A>\n");
	printf("for more information about our society");
	sprintf(filename, "%s/users.html", HTTPD_DOCUMENT_ROOT);
	if (!access(calcpath(filename), F_OK))
		printf(" or the <A HREF=\"/users.html\">user list</A>\n");
	printf(".\n");
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
	printf("Content-type: text/html\r\n");
	printf("Status: %s\r\n\r\n", error_readable);
	printf("<HTML><HEAD><TITLE>%s</TITLE></HEAD>", error_readable);
	printf("<BODY><H1>%s</H1>\n", error_readable);
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
	printf("</BODY></HTML>\n");
	(void)argc;
	(void)argv;
	exit(0);
}
