# Language coverage controls

Never execute these fixtures. Tests copy source into an owned temporary target and run offline recon.

`lang_elixir_vulnerable` preserves the credential-redacted Elixir example and `mix.exs` supplied in
[PR 151's immutable regression source](https://github.com/raccioly/websec-validator/blob/9f93abae0930523ffefb86da7a82be06a482336f/tests/test_unanalyzed_coverage.py).
The application was inline, not a separately committed fixture directory. Terminal newline differences
do not change the reproduced source behavior.

`lang_swift_vulnerable` is a newly authored synthetic control. The original PR's complete tree,
history, body and comments contain no Swift application source. It must not be described as an
unchanged replay of V9 or evidence that its original vulnerabilities were recovered.

These assert unsupported/thin-language disclosure in actual persisted CLI artifacts, not vulnerability
recall, successful exploitation, or a new language analyzer. The original Swift acceptance evidence
in spec 002 FR-013/SC-005 remains unavailable.
