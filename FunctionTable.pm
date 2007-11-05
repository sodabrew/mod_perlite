package ModPerl::FunctionTable;

$ModPerl::FunctionTable = [
  {
    'return_type' => 'void',
    'name' => 'modperl_io_apache_init',
    'attr' => [
      '__inline__'
    ],
    'args' => [
      {
        'type' => 'PerlInterpreter *',
        'name' => 'my_perl'
      }
    ]
  },
  {
    'return_type' => 'void',
    'name' => 'modperl_io_handle_tie',
    'attr' => [
      '__inline__'
    ],
    'args' => [
      {
        'type' => 'PerlInterpreter *',
        'name' => 'my_perl'
      },
      {
        'type' => 'GV *',
        'name' => 'handle'
      },
      {
        'type' => 'char *',
        'name' => 'classname'
      },
      {
        'type' => 'void *',
        'name' => 'ptr'
      }
    ]
  },
  {
    'return_type' => 'int',
    'name' => 'modperl_io_handle_tied',
    'attr' => [
      '__inline__'
    ],
    'args' => [
      {
        'type' => 'PerlInterpreter *',
        'name' => 'my_perl'
      },
      {
        'type' => 'GV *',
        'name' => 'handle'
      },
      {
        'type' => 'char *',
        'name' => 'classname'
      }
    ]
  },
  {
    'return_type' => 'void',
    'name' => 'modperl_io_handle_untie',
    'attr' => [
      '__inline__'
    ],
    'args' => [
      {
        'type' => 'PerlInterpreter *',
        'name' => 'my_perl'
      },
      {
        'type' => 'GV *',
        'name' => 'handle'
      }
    ]
  },
  {
    'return_type' => 'GV *',
    'name' => 'modperl_io_perlio_override_stdin',
    'attr' => [
      '__inline__'
    ],
    'args' => [
      {
        'type' => 'PerlInterpreter *',
        'name' => 'my_perl'
      },
      {
        'type' => 'request_rec *',
        'name' => 'r'
      }
    ]
  },
  {
    'return_type' => 'GV *',
    'name' => 'modperl_io_perlio_override_stdout',
    'attr' => [
      '__inline__'
    ],
    'args' => [
      {
        'type' => 'PerlInterpreter *',
        'name' => 'my_perl'
      },
      {
        'type' => 'request_rec *',
        'name' => 'r'
      }
    ]
  },
  {
    'return_type' => 'void',
    'name' => 'modperl_io_perlio_restore_stdin',
    'attr' => [
      '__inline__'
    ],
    'args' => [
      {
        'type' => 'PerlInterpreter *',
        'name' => 'my_perl'
      },
      {
        'type' => 'GV *',
        'name' => 'handle'
      }
    ]
  },
  {
    'return_type' => 'void',
    'name' => 'modperl_io_perlio_restore_stdout',
    'attr' => [
      '__inline__'
    ],
    'args' => [
      {
        'type' => 'PerlInterpreter *',
        'name' => 'my_perl'
      },
      {
        'type' => 'GV *',
        'name' => 'handle'
      }
    ]
  },
  {
    'return_type' => 'GV *',
    'name' => 'modperl_io_tie_stdin',
    'attr' => [
      '__inline__'
    ],
    'args' => [
      {
        'type' => 'PerlInterpreter *',
        'name' => 'my_perl'
      },
      {
        'type' => 'request_rec *',
        'name' => 'r'
      }
    ]
  },
  {
    'return_type' => 'GV *',
    'name' => 'modperl_io_tie_stdout',
    'attr' => [
      '__inline__'
    ],
    'args' => [
      {
        'type' => 'PerlInterpreter *',
        'name' => 'my_perl'
      },
      {
        'type' => 'request_rec *',
        'name' => 'r'
      }
    ]
  },
];


1;
