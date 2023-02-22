/* A Bison parser, made by GNU Bison 3.5.1.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.5.1"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Substitute the type names.  */
#define YYSTYPE         NGX_HTTP_WAF_STYPE
/* Substitute the variable and function names.  */
#define yyparse         ngx_http_waf_parse
#define yylex           ngx_http_waf_lex
#define yyerror         ngx_http_waf_error
#define yydebug         ngx_http_waf_debug
#define yynerrs         ngx_http_waf_nerrs
#define yylval          ngx_http_waf_lval
#define yychar          ngx_http_waf_char

/* First part of user prologue.  */
#line 1 "bison/parser.yacc"

    #include <ngx_http_waf_module_type.h>
    #include <ngx_http_waf_module_util.h>
    #include <ngx_http_waf_module_lexer.h>
    #include <math.h>
    #include <stdio.h>
    #include <utarray.h>
    #include <ngx_core.h>
    int ngx_http_waf_lex (void);
    void ngx_http_waf_error (UT_array* array, ngx_pool_t* pool, const char* msg);
    void ngx_http_waf_gen_push_str_code(UT_array* array, char* str);
    void ngx_http_waf_gen_push_client_ip_code(UT_array* array);
    void ngx_http_waf_gen_push_url_code(UT_array* array);
    void ngx_http_waf_gen_push_user_agent_code(UT_array* array);
    void ngx_http_waf_gen_push_referer_code(UT_array* array);
    void ngx_http_waf_gen_push_query_string_code(UT_array* array, char* index);
    void ngx_http_waf_gen_push_header_in_code(UT_array* array, char* index);
    void ngx_http_waf_gen_push_cookie_code(UT_array* array, char* index);
    void ngx_http_waf_gen_int_code(UT_array* array, int num);
    void ngx_http_waf_gen_push_op_not_code(UT_array* array);
    void ngx_http_waf_gen_op_and_code(UT_array* array);
    void ngx_http_waf_gen_op_or_code(UT_array* array);
    void ngx_http_waf_gen_op_matches_code(UT_array* array);
    void ngx_http_waf_gen_op_contains_code(UT_array* array);
    void ngx_http_waf_gen_op_equals_code(UT_array* array);
    void ngx_http_waf_gen_op_belong_to_code(UT_array* array);
    void ngx_http_waf_gen_op_sqli_detn_code(UT_array* array);
    void ngx_http_waf_gen_op_xss_detn_code(UT_array* array);
    void ngx_http_waf_gen_act_ret_code(UT_array* array, int http_status);
    void ngx_http_waf_gen_act_allow_code(UT_array* array);

#line 110 "src/ngx_http_waf_module_parser.tab.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_NGX_HTTP_WAF_INC_NGX_HTTP_WAF_MODULE_PARSER_TAB_H_INCLUDED
# define YY_NGX_HTTP_WAF_INC_NGX_HTTP_WAF_MODULE_PARSER_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef NGX_HTTP_WAF_DEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define NGX_HTTP_WAF_DEBUG 1
#  else
#   define NGX_HTTP_WAF_DEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define NGX_HTTP_WAF_DEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined NGX_HTTP_WAF_DEBUG */
#if NGX_HTTP_WAF_DEBUG
extern int ngx_http_waf_debug;
#endif

/* Token type.  */
#ifndef NGX_HTTP_WAF_TOKENTYPE
# define NGX_HTTP_WAF_TOKENTYPE
  enum ngx_http_waf_tokentype
  {
    token_id = 258,
    token_str = 259,
    token_index = 260,
    token_int = 261,
    keyword_id = 262,
    keyword_if = 263,
    keyword_do = 264,
    keyword_or = 265,
    keyword_allow = 266,
    keyword_and = 267,
    keyword_matches = 268,
    keyword_equals = 269,
    token_break_line = 270,
    token_blank = 271,
    keyword_not = 272,
    keyword_url = 273,
    keyword_contains = 274,
    keyword_return = 275,
    keyword_query_string = 276,
    keyword_user_agent = 277,
    keyword_belong_to = 278,
    keyword_referer = 279,
    keyword_client_ip = 280,
    keyword_header_in = 281,
    keyword_sqli_detn = 282,
    keyword_xss_detn = 283,
    keyword_cookie = 284
  };
#endif

/* Value type.  */
#if ! defined NGX_HTTP_WAF_STYPE && ! defined NGX_HTTP_WAF_STYPE_IS_DECLARED
union NGX_HTTP_WAF_STYPE
{
#line 53 "bison/parser.yacc"

    int             int_val;
    unsigned int    uint_val;
    char            id_val[256];
    char            str_val[256];
    void            (*push_op_code_pt)(UT_array* array);
    struct {
        int argc;
        void (*no_str_pt)(UT_array* array);
        void (*one_str_pt)(UT_array* array, char* str);
        char* argv[4];
    } push_str_code_info;

#line 214 "src/ngx_http_waf_module_parser.tab.c"

};
typedef union NGX_HTTP_WAF_STYPE NGX_HTTP_WAF_STYPE;
# define NGX_HTTP_WAF_STYPE_IS_TRIVIAL 1
# define NGX_HTTP_WAF_STYPE_IS_DECLARED 1
#endif


extern NGX_HTTP_WAF_STYPE ngx_http_waf_lval;

int ngx_http_waf_parse (UT_array* array, ngx_pool_t* pool);

#endif /* !YY_NGX_HTTP_WAF_INC_NGX_HTTP_WAF_MODULE_PARSER_TAB_H_INCLUDED  */



#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))

/* Stored state numbers (used for stacks). */
typedef yytype_int8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                            \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined NGX_HTTP_WAF_STYPE_IS_TRIVIAL && NGX_HTTP_WAF_STYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  6
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   78

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  33
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  13
/* YYNRULES -- Number of rules.  */
#define YYNRULES  35
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  78

#define YYUNDEFTOK  2
#define YYMAXUTOK   284


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      31,    32,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    30,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29
};

#if NGX_HTTP_WAF_DEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,    73,    73,    76,    81,    85,    86,    87,    92,    97,
     102,   107,   114,   119,   124,   128,   132,   134,   139,   165,
     192,   207,   222,   238,   258,   264,   270,   276,   283,   290,
     297,   306,   311,   316,   323,   328
};
#endif

#if NGX_HTTP_WAF_DEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "token_id", "token_str", "token_index",
  "token_int", "keyword_id", "keyword_if", "keyword_do", "keyword_or",
  "keyword_allow", "keyword_and", "keyword_matches", "keyword_equals",
  "token_break_line", "token_blank", "keyword_not", "keyword_url",
  "keyword_contains", "keyword_return", "keyword_query_string",
  "keyword_user_agent", "keyword_belong_to", "keyword_referer",
  "keyword_client_ip", "keyword_header_in", "keyword_sqli_detn",
  "keyword_xss_detn", "keyword_cookie", "':'", "'('", "')'", "$accept",
  "str_operand", "str_op", "ip_op", "base", "rule", "end", "id_rule",
  "if_rule", "do_rule", "conditon", "conditon_ex", "primary", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_int16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
      58,    40,    41
};
# endif

#define YYPACT_NINF (-44)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int8 yypact[] =
{
       5,   -12,    19,     7,    12,    25,   -44,     8,   -44,    14,
      37,    52,     5,    40,    27,   -44,    44,   -44,     9,    45,
     -44,   -44,    46,   -44,    55,   -44,   -44,    -7,    58,    48,
      49,    61,     9,    35,    -1,    57,   -44,    -5,    38,   -44,
     -44,    51,   -44,    21,   -44,    21,    21,   -44,   -11,   -44,
     -44,    53,   -44,    21,     9,   -44,     9,   -44,    41,     9,
      -6,   -44,   -44,   -44,   -44,    39,   -44,    57,   -44,    65,
      -8,    21,    21,    42,   -44,   -44,   -44,   -44
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       3,     0,     0,     7,     0,     0,     1,     0,     2,     0,
       0,     0,     6,     0,     0,     4,     0,     5,     0,     0,
       8,    27,     0,    24,     0,    25,    26,     0,     0,     0,
       0,     0,     0,     0,     0,    13,    15,     0,     0,    29,
      34,     0,    35,     0,    28,     0,     0,    30,     0,    32,
      33,     0,    31,     0,     0,     9,     0,    11,     0,     0,
       0,    22,    20,    21,    16,     0,    18,    12,    14,     0,
       0,     0,     0,     0,    17,    23,    19,    10
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -44,   -43,    10,    13,   -44,    64,   -44,   -44,   -44,   -44,
     -27,    23,    22
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
      -1,    33,    53,    43,     2,     3,     8,     4,    10,    15,
      34,    35,    36
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int8 yytable[] =
{
      61,    54,    62,    63,    54,    48,    57,    40,    40,    41,
      66,    54,     1,    21,    55,    58,    42,    42,     5,     6,
       9,    64,     7,    12,    74,    21,    22,    23,    75,    76,
      24,    25,    70,    26,    27,    28,    29,    30,    31,    23,
      32,    11,    24,    25,    13,    26,    14,    28,    49,    50,
      31,    51,    49,    50,    52,    16,    18,    19,    52,    20,
      39,    37,    38,    44,    45,    46,    47,    56,    60,    59,
      65,    73,    69,    71,    77,    72,    17,    67,    68
};

static const yytype_int8 yycheck[] =
{
      43,    12,    45,    46,    12,    32,    11,    14,    14,    16,
      53,    12,     7,     4,    15,    20,    23,    23,    30,     0,
       8,    32,    15,    15,    32,     4,    17,    18,    71,    72,
      21,    22,    59,    24,    25,    26,    27,    28,    29,    18,
      31,    16,    21,    22,    30,    24,     9,    26,    13,    14,
      29,    16,    13,    14,    19,     3,    16,    30,    19,    15,
       5,    16,    16,     5,    16,    16,     5,    10,    17,    31,
      17,     6,    31,    60,    32,    65,    12,    54,    56
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     7,    37,    38,    40,    30,     0,    15,    39,     8,
      41,    16,    15,    30,     9,    42,     3,    38,    16,    30,
      15,     4,    17,    18,    21,    22,    24,    25,    26,    27,
      28,    29,    31,    34,    43,    44,    45,    16,    16,     5,
      14,    16,    23,    36,     5,    16,    16,     5,    43,    13,
      14,    16,    19,    35,    12,    15,    10,    11,    20,    31,
      17,    34,    34,    34,    32,    17,    34,    44,    45,    31,
      43,    36,    35,     6,    32,    34,    34,    32
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_int8 yyr1[] =
{
       0,    33,    37,    37,    38,    39,    39,    39,    40,    41,
      42,    42,    43,    43,    44,    44,    45,    45,    45,    45,
      45,    45,    45,    45,    34,    34,    34,    34,    34,    34,
      34,    35,    35,    35,    36,    36
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     2,     0,     3,     3,     2,     0,     5,     5,
       7,     4,     3,     1,     3,     1,     3,     5,     3,     5,
       3,     3,     3,     5,     1,     1,     1,     1,     2,     2,
       2,     1,     1,     1,     1,     1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (array, pool, YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if NGX_HTTP_WAF_DEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, array, pool); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep, UT_array* array, ngx_pool_t* pool)
{
  FILE *yyoutput = yyo;
  YYUSE (yyoutput);
  YYUSE (array);
  YYUSE (pool);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yytype], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep, UT_array* array, ngx_pool_t* pool)
{
  YYFPRINTF (yyo, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyo, yytype, yyvaluep, array, pool);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp, int yyrule, UT_array* array, ngx_pool_t* pool)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[+yyssp[yyi + 1 - yynrhs]],
                       &yyvsp[(yyi + 1) - (yynrhs)]
                                              , array, pool);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, array, pool); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !NGX_HTTP_WAF_DEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !NGX_HTTP_WAF_DEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
#  else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                yy_state_t *yyssp, int yytoken)
{
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Actual size of YYARG. */
  int yycount = 0;
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[+*yyssp];
      YYPTRDIFF_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
      yysize = yysize0;
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYPTRDIFF_T yysize1
                    = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
                    yysize = yysize1;
                  else
                    return 2;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    /* Don't count the "%s"s in the final size, but reserve room for
       the terminator.  */
    YYPTRDIFF_T yysize1 = yysize + (yystrlen (yyformat) - 2 * yycount) + 1;
    if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
      yysize = yysize1;
    else
      return 2;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, UT_array* array, ngx_pool_t* pool)
{
  YYUSE (yyvaluep);
  YYUSE (array);
  YYUSE (pool);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

int
yyparse (UT_array* array, ngx_pool_t* pool)
{
    yy_state_fast_t yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss;
    yy_state_t *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYPTRDIFF_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    goto yyexhaustedlab;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
# undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 2:
#line 74 "bison/parser.yacc"
        {}
#line 1440 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 3:
#line 77 "bison/parser.yacc"
        {}
#line 1446 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 4:
#line 82 "bison/parser.yacc"
        {}
#line 1452 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 5:
#line 85 "bison/parser.yacc"
                                               { }
#line 1458 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 6:
#line 86 "bison/parser.yacc"
                                             {  }
#line 1464 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 7:
#line 87 "bison/parser.yacc"
               { }
#line 1470 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 8:
#line 93 "bison/parser.yacc"
        { ngx_http_waf_gen_push_str_code(array, (yyvsp[-1].id_val)); }
#line 1476 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 9:
#line 98 "bison/parser.yacc"
        {  }
#line 1482 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 10:
#line 103 "bison/parser.yacc"
        { 
            ngx_http_waf_gen_act_ret_code(array, (yyvsp[-1].int_val));                   
        }
#line 1490 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 11:
#line 108 "bison/parser.yacc"
        { 
            ngx_http_waf_gen_act_allow_code(array);                   
        }
#line 1498 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 12:
#line 115 "bison/parser.yacc"
        { 
            ngx_http_waf_gen_op_and_code(array);
        }
#line 1506 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 13:
#line 120 "bison/parser.yacc"
        {  }
#line 1512 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 14:
#line 125 "bison/parser.yacc"
        { 
            ngx_http_waf_gen_op_or_code(array);
        }
#line 1520 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 15:
#line 129 "bison/parser.yacc"
        {  }
#line 1526 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 16:
#line 132 "bison/parser.yacc"
                           {  }
#line 1532 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 17:
#line 135 "bison/parser.yacc"
        {
            ngx_http_waf_gen_push_op_not_code(array);
        }
#line 1540 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 18:
#line 140 "bison/parser.yacc"
        {
            switch ((yyvsp[0].push_str_code_info).argc) {
                case 0:
                    (yyvsp[0].push_str_code_info).no_str_pt(array);
                    break;
                case 1:
                    (yyvsp[0].push_str_code_info).one_str_pt(array, (yyvsp[0].push_str_code_info).argv[0]);
                    break;
                default:
                    YYABORT;
            }

            switch ((yyvsp[-2].push_str_code_info).argc) {
                case 0:
                    (yyvsp[-2].push_str_code_info).no_str_pt(array);
                    break;
                case 1:
                    (yyvsp[-2].push_str_code_info).one_str_pt(array, (yyvsp[-2].push_str_code_info).argv[0]);
                    break;
                default:
                    YYABORT;
            }
            (yyvsp[-1].push_op_code_pt)(array);
        }
#line 1569 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 19:
#line 166 "bison/parser.yacc"
        {
            switch ((yyvsp[0].push_str_code_info).argc) {
                case 0:
                    (yyvsp[0].push_str_code_info).no_str_pt(array);
                    break;
                case 1:
                    (yyvsp[0].push_str_code_info).one_str_pt(array, (yyvsp[0].push_str_code_info).argv[0]);
                    break;
                default:
                    YYABORT;
            }

            switch ((yyvsp[-4].push_str_code_info).argc) {
                case 0:
                    (yyvsp[-4].push_str_code_info).no_str_pt(array);
                    break;
                case 1:
                    (yyvsp[-4].push_str_code_info).one_str_pt(array, (yyvsp[-4].push_str_code_info).argv[0]);
                    break;
                default:
                    YYABORT;
            }
            (yyvsp[-1].push_op_code_pt)(array);
            ngx_http_waf_gen_push_op_not_code(array);
        }
#line 1599 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 20:
#line 193 "bison/parser.yacc"
        {
            switch ((yyvsp[0].push_str_code_info).argc) {
                case 0:
                    (yyvsp[0].push_str_code_info).no_str_pt(array);
                    break;
                case 1:
                    (yyvsp[0].push_str_code_info).one_str_pt(array, (yyvsp[0].push_str_code_info).argv[0]);
                    break;
                default:
                    YYABORT;
            }
            ngx_http_waf_gen_op_sqli_detn_code(array);
        }
#line 1617 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 21:
#line 208 "bison/parser.yacc"
        {
            switch ((yyvsp[0].push_str_code_info).argc) {
                case 0:
                    (yyvsp[0].push_str_code_info).no_str_pt(array);
                    break;
                case 1:
                    (yyvsp[0].push_str_code_info).one_str_pt(array, (yyvsp[0].push_str_code_info).argv[0]);
                    break;
                default:
                    YYABORT;
            }
            ngx_http_waf_gen_op_xss_detn_code(array);
        }
#line 1635 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 22:
#line 223 "bison/parser.yacc"
        {
            switch ((yyvsp[0].push_str_code_info).argc) {
                case 0:
                    (yyvsp[0].push_str_code_info).no_str_pt(array);
                    break;
                case 1:
                    (yyvsp[0].push_str_code_info).one_str_pt(array, (yyvsp[0].push_str_code_info).argv[0]);
                    break;
                default:
                    YYABORT;
            }
            ngx_http_waf_gen_push_client_ip_code(array);
            (yyvsp[-1].push_op_code_pt)(array);
        }
#line 1654 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 23:
#line 239 "bison/parser.yacc"
        {
            switch ((yyvsp[0].push_str_code_info).argc) {
                case 0:
                    (yyvsp[0].push_str_code_info).no_str_pt(array);
                    break;
                case 1:
                    (yyvsp[0].push_str_code_info).one_str_pt(array, (yyvsp[0].push_str_code_info).argv[0]);
                    break;
                default:
                    YYABORT;
            }
            ngx_http_waf_gen_push_client_ip_code(array);
            (yyvsp[-1].push_op_code_pt)(array);
            ngx_http_waf_gen_push_op_not_code(array);
        }
#line 1674 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 24:
#line 259 "bison/parser.yacc"
        {
            (yyval.push_str_code_info).argc = 0;
            (yyval.push_str_code_info).no_str_pt = ngx_http_waf_gen_push_url_code;
        }
#line 1683 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 25:
#line 265 "bison/parser.yacc"
        {
            (yyval.push_str_code_info).argc = 0;
            (yyval.push_str_code_info).no_str_pt = ngx_http_waf_gen_push_user_agent_code;
        }
#line 1692 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 26:
#line 271 "bison/parser.yacc"
        {
            (yyval.push_str_code_info).argc = 0;
            (yyval.push_str_code_info).no_str_pt = ngx_http_waf_gen_push_referer_code;
        }
#line 1701 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 27:
#line 277 "bison/parser.yacc"
        {
            (yyval.push_str_code_info).argc = 1;
            (yyval.push_str_code_info).one_str_pt = ngx_http_waf_gen_push_str_code;
            (yyval.push_str_code_info).argv[0] = strdup((yyvsp[0].str_val));
        }
#line 1711 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 28:
#line 284 "bison/parser.yacc"
        {
            (yyval.push_str_code_info).argc = 1;
            (yyval.push_str_code_info).one_str_pt = ngx_http_waf_gen_push_header_in_code;
            (yyval.push_str_code_info).argv[0] = strdup((yyvsp[0].str_val));
        }
#line 1721 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 29:
#line 291 "bison/parser.yacc"
        {
            (yyval.push_str_code_info).argc = 1;
            (yyval.push_str_code_info).one_str_pt = ngx_http_waf_gen_push_query_string_code;
            (yyval.push_str_code_info).argv[0] = strdup((yyvsp[0].str_val));
        }
#line 1731 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 30:
#line 298 "bison/parser.yacc"
        {
            (yyval.push_str_code_info).argc = 1;
            (yyval.push_str_code_info).one_str_pt = ngx_http_waf_gen_push_cookie_code;
            (yyval.push_str_code_info).argv[0] = strdup((yyvsp[0].str_val));
        }
#line 1741 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 31:
#line 307 "bison/parser.yacc"
        {
            (yyval.push_op_code_pt) = ngx_http_waf_gen_op_contains_code;
        }
#line 1749 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 32:
#line 312 "bison/parser.yacc"
        {
            (yyval.push_op_code_pt) = ngx_http_waf_gen_op_matches_code;
        }
#line 1757 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 33:
#line 317 "bison/parser.yacc"
        {
            (yyval.push_op_code_pt) = ngx_http_waf_gen_op_equals_code;
        }
#line 1765 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 34:
#line 324 "bison/parser.yacc"
        {
            (yyval.push_op_code_pt) = ngx_http_waf_gen_op_equals_code;
        }
#line 1773 "src/ngx_http_waf_module_parser.tab.c"
    break;

  case 35:
#line 329 "bison/parser.yacc"
        {
            (yyval.push_op_code_pt) = ngx_http_waf_gen_op_belong_to_code;
        }
#line 1781 "src/ngx_http_waf_module_parser.tab.c"
    break;


#line 1785 "src/ngx_http_waf_module_parser.tab.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (array, pool, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *, YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (array, pool, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, array, pool);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp, array, pool);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;


#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (array, pool, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif


/*-----------------------------------------------------.
| yyreturn -- parsing is finished, return the result.  |
`-----------------------------------------------------*/
yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, array, pool);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[+*yyssp], yyvsp, array, pool);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 333 "bison/parser.yacc"



void
ngx_http_waf_gen_push_str_code(UT_array* array, char* str) {
    vm_code_t code;

    code.type = VM_CODE_PUSH_STR;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_STR;
    code.argv.value[0].str_val.data = (u_char*)strdup(str);
    code.argv.value[0].str_val.len = strlen(str);

    utarray_push_back(array, &code);
    free(code.argv.value[0].str_val.data);
}


void ngx_http_waf_gen_push_query_string_code(UT_array* array, char* index) {
    vm_code_t code;
    size_t len = strlen(index);
    code.type = VM_CODE_PUSH_QUERY_STRING;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_STR;
    code.argv.value[0].str_val.data = (u_char*)strdup(index);
    code.argv.value[0].str_val.len = len;

    utarray_push_back(array, &code);
    free(code.argv.value[0].str_val.data);
}


void ngx_http_waf_gen_push_header_in_code(UT_array* array, char* index) {
    vm_code_t code;
    size_t len = strlen(index);
    code.type = VM_CODE_PUSH_HEADER_IN;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_STR;
    code.argv.value[0].str_val.data = (u_char*)strdup(index);
    code.argv.value[0].str_val.len = len;

    utarray_push_back(array, &code);
    free(code.argv.value[0].str_val.data);
}


void ngx_http_waf_gen_push_cookie_code(UT_array* array, char* index) {
    vm_code_t code;
    size_t len = strlen(index);
    code.type = VM_CODE_PUSH_COOKIE;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_STR;
    code.argv.value[0].str_val.data = (u_char*)strdup(index);
    code.argv.value[0].str_val.len = len;

    utarray_push_back(array, &code);
    free(code.argv.value[0].str_val.data);
}


void ngx_http_waf_gen_push_client_ip_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_PUSH_CLIENT_IP;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_push_url_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_PUSH_URL;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_push_user_agent_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_PUSH_USER_AGENT;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_push_referer_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_PUSH_REFERER;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_int_code(UT_array* array, int num) {
    vm_code_t code;
    code.type = VM_CODE_PUSH_INT;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_INT;
    code.argv.value[0].int_val = num;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_push_op_not_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_NOT;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_and_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_AND;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_or_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_OR;;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}

void
ngx_http_waf_gen_op_matches_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_MATCHES;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}



void
ngx_http_waf_gen_op_contains_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_CONTAINS;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_equals_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_EQUALS;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_belong_to_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_BELONG_TO;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_sqli_detn_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_SQLI_DETN;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_xss_detn_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_XSS_DETN;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_act_ret_code(UT_array* array, int http_status) {
    vm_code_t code;
    code.type = VM_CODE_ACT_RETURN;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_INT;
    code.argv.value[0].int_val = http_status;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_act_allow_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_ACT_ALLOW;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}
