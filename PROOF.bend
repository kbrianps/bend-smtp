# The proofs of LAWS.bend. `bend PROOF.bend` prints "All terms check."
# once every law holds.
import Base
import ./text.bend as T
import ./reply.bend as R
import ./smtp.bend as S
import ./sink.bend as K
import ./mime.bend as M
import ./idna.bend as I
import ./addr.bend as A
import ./md5.bend as D
import ./dkim.bend as Q
import ./LAWS.bend as Laws

# One cleaned char on a clean rest: a newline is dropped, any other
# char is kept, and either way no newline comes out.
def Lemma.clean_put(
  b: Bool, c: Char, r: String,
  ih: {T.Text.has_nl(r) == False{} : Bool},
  e: {b == T.Text.is_nl(c) : Bool}
) -> {T.Text.has_nl(T.Text.clean.put(b, c, r)) == False{} : Bool}:
  match b:
    case True{}:
      ih
    case False{}:
      %e : {Bool.or(_, T.Text.has_nl(r)) == False{} : Bool}
      ih

def Laws.clean_safe(s):
  match s:
    case SNil{}:
      {==}
    case SCon{+c, +t}:
      Lemma.clean_put(T.Text.is_nl(c), c, T.Text.clean(t), Laws.clean_safe(t),
        {==})

def Laws.subject_one_line():
  {==}

def Laws.reply_multiline():
  {==}

def Laws.reply_partial():
  {==}

def Laws.reply_broken():
  {==}

def Laws.data_stuffed():
  {==}

def Laws.sink_quit(from, n, data):
  {==}

def Laws.sink_data_needs_rcpt(from, data):
  {==}

def Laws.sink_dot_saves(from, n, data):
  {==}

def Laws.sink_unstuffs():
  {==}

def Laws.base64_vectors():
  {==}

def Laws.base64_utf8():
  {==}

def Laws.auth_plain():
  {==}

def Laws.date_header():
  {==}

def Laws.subject_encoding():
  {==}

def Laws.subject_folds():
  {==}

def Laws.body_encoding():
  {==}

def Laws.body_long_line():
  {==}

def Laws.mail_params():
  {==}

def Laws.ehlo_caps():
  {==}

def Laws.addresses():
  {==}

def Laws.sink_nested_mail():
  {==}

def Laws.sink_ehlo_resets(from, n, data):
  {==}

def Laws.sink_verbs():
  {==}

def Laws.sink_starttls(from, n, data):
  {==}

def Laws.sink_starttls_refused():
  {==}

def Laws.punycode():
  {==}

def Laws.needs_smtputf8():
  {==}

def Laws.domain_to_alabel():
  {==}

def Laws.xoauth2_vector():
  {==}

def Laws.oauthbearer_vector():
  {==}

def Laws.mechanism_choice():
  {==}

def Laws.base64_decode():
  {==}

def Laws.mailbox_list():
  {==}

def Laws.mailbox_show():
  {==}

def Laws.rcpt_list():
  {==}

def Laws.bcc_hidden():
  {==}

def Laws.multipart_shape():
  {==}

def Laws.filename_2231():
  {==}

def Laws.boundary_safe():
  {==}

def Laws.extra_headers():
  {==}

def Laws.header_names():
  {==}

def Laws.batch_keeps_order(a, b, code, error):
  {==}

def Laws.dsn_rcpt():
  {==}

def Laws.plan_follows_offers():
  {==}

def Laws.pipeline_blob():
  {==}

def Laws.md5_vectors():
  {==}

def Laws.cram_md5_vector():
  {==}

def Laws.cram_choice():
  {==}

def Laws.proxy_url():
  {==}

def Laws.dkim_signed_data():
  {==}

def Laws.dkim_relaxed():
  {==}

def Laws.dkim_fields():
  ({==}, {==})

def Laws.refusal_kept(x, y, code, error):
  ({==}, {==})

def Laws.proxy_never_skipped():
  {==}

def Laws.dkim_simple():
  {==}

def Laws.dkim_simple_data():
  {==}
