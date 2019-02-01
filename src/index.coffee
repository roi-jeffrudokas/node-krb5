k = require '../build/Release/krb5'
fs = require 'fs'


cleanup = (ctx, princ, ccache) ->
  k.krb5_free_principal_sync ctx, princ if princ
  
  if ccache
    k.krb5_cc_close ctx, ccache, (err) ->
      k.krb5_free_context_sync ctx if ctx
  else
    k.krb5_free_context_sync ctx if ctx


handle_error = (callback, err, ctx, princ, ccache) ->
  return err unless err
  err = k.krb5_get_error_message_sync(ctx, err)
  cleanup ctx, princ, ccache
  return callback Error err


kinit = (options, callback) ->
  return callback Error 'Please specify principal for kinit' unless options.principal
  return callback Error 'Please specify password or keytab for kinit' unless options.password or options.keytab

  if options.principal.indexOf('@') != -1
    split = options.principal.split('@')
    options.principal = split[0]
    options.realm = split[1]

  do_init = ->
    k.krb5_init_context (err, ctx) ->
      return handle_error callback, err if err
      do_realm ctx

  do_realm = (ctx) ->
    if !options.realm
      k.krb5_get_default_realm ctx, (err, realm) ->
        return handle_error callback, err, ctx if err
        options.realm = realm
        do_principal ctx
    else
      do_principal ctx

  do_principal = (ctx) ->
    k.krb5_build_principal ctx,
    options.realm.length,
    options.realm,
    options.principal,
    (err, princ) ->
      return handle_error callback, err, ctx if err
      do_ccache ctx, princ

  do_ccache = (ctx, princ) ->
    if options.ccname
      if options.ccname.indexOf(':KEYRING') != -1
        cleanup ctx, princ
        return callback Error 'KEYRING method not supported.'
      k.krb5_cc_resolve ctx, options.ccname, (err, ccache) ->
        return handle_error callback, err, ctx, princ if err
        do_creds ctx, princ, ccache
    else
      k.krb5_cc_default ctx, (err, ccache) ->
        return handle_error callback, err, ctx, princ if err
        do_creds ctx, princ, ccache

  do_creds = (ctx, princ, ccache) ->
    ccname = k.krb5_cc_get_name_sync ctx, ccache
    fs.exists ccname, (exists) ->
      if !exists
        k.krb5_cc_initialize ctx, ccache, princ, (err) ->
          return handle_error callback, err, ctx, princ if err
          if options.password then get_creds_password() else get_creds_keytab()
      else
        if options.password then get_creds_password() else get_creds_keytab()
      
    get_creds_password = ->
      k.krb5_get_init_creds_password ctx, princ, options.password, (err, creds) ->
        return handle_error callback, err, ctx, princ, ccache if err
        store_creds creds

    get_creds_keytab = ->
      k.krb5_kt_resolve ctx, options.keytab, (err, kt) ->
        return handle_error callback, err, ctx, princ, ccache if err
        k.krb5_get_init_creds_keytab ctx, princ, kt, 0, (err, creds) ->
          return handle_error callback, err, ctx, princ, ccache if err
          store_creds creds
            
    store_creds = (creds) ->
      k.krb5_cc_store_cred ctx, ccache, creds, (err) ->
        return handle_error callback, err, ctx, princ, ccache if err
        cleanup ctx, princ, ccache
        callback undefined, ccname
  
  do_init()


kdestroy = (options, callback) ->
  k.krb5_init_context (err, ctx) ->
    return handle_error(callback, err, ctx) if err
    do_ccache(ctx)

  do_ccache = (ctx) ->
    if options.ccname
      k.krb5_cc_resolve ctx, options.ccname, (err, ccache) ->
        return handle_error(callback, err, ctx, null, ccache) if err
        do_destroy ctx, ccache
    else
      k.krb5_cc_default ctx, (err, ccache) ->
        return handle_error(callback, err, ctx, null, ccache) if err
        do_destroy ctx, ccache

  do_destroy = (ctx, ccache) ->
    k.krb5_cc_destroy ctx, ccache, (err) ->
      return handle_error(callback, err, ctx) if err
      callback undefined

kvno = (options, callback) ->
  return callback Error 'Please specify service for kvno' unless options.service

  k.krb5_init_context (err, ctx) ->
    return handle_error(callback, err, ctx) if err
    do_ccache(ctx)

  do_ccache = (ctx) ->
    if options.ccname
      k.krb5_cc_resolve ctx, options.ccname, (err, ccache) ->
        return handle_error(callback, err, ctx) if err
        do_keytab ctx, ccache
    else
      k.krb5_cc_default ctx, (err, ccache) ->
        return handle_error(callback, err, ctx) if err
        do_keytab ctx, ccache

  do_keytab = (ctx, ccache) ->
    if options.keytab
      k.krb5_kt_resolve ctx, options.keytab, (err, keytab) ->
        return handle_error(callback, err, ctx) if err
        do_for_user ctx, ccache, keytab
    else
        do_for_user ctx, ccache, null

  do_for_user = (ctx, ccache, keytab) ->
    if options.foruser
      k.krb5_parse_name_flags ctx, options.foruser, (err, foruser_princ) ->
        return handle_error(callback, err, ctx, null, ccache) if err
        do_me ctx, ccache, keytab, foruser_princ
    else
      do_me ctx, ccache, keytab, null

  # unhandled options
    # do_u2u
    # do_etype

  do_me = (ctx, ccache, keytab, foruser_princ) ->
    k.krb5_cc_get_principal ctx, ccache, (err, me) ->
      return handle_error(callback, err, ctx, null, ccache) if err
      do_parse_name ctx, ccache, keytab, foruser_princ, me

  do_parse_name = (ctx, ccache, keytab, foruser_princ, me) ->
    if options.sname
      k.krb5_sname_to_principal ctx, options.service, options.sname, (err, server) ->
        return handle_error(callback, err, ctx, null, ccache) if err
        do_creds ctx, ccache, keytab, foruser_princ, me, server
    else
      k.krb5_parse_name ctx, options.service, (err, server) ->
        return handle_error(callback, err, ctx, null, ccache) if err
        do_creds ctx, ccache, keytab, foruser_princ, me, server

  do_creds = (ctx, ccache, keytab, foruser_princ, me, server) ->
    opt = 0
    if foruser_princ is not null
      # TODO: error if !krb5_principal_compare(ctx, me, server)
      k.krb5_get_credentials_for_user ctx,  # unhandled in_cred_etype, in_cred_u2u
      opt,
      ccache,
      foruser_princ,  # in_cred_client,
      me,             # in_cred_server
      null,
      (err, out_creds) ->
        return handle_error(callback, err, ctx, null, ccache) if err
        callback undefined
    else
      k.krb5_get_credentials ctx,  # unhandled in_cred_etype, in_cred_u2u
      opt,
      ccache,
      me,             # in_cred_client,
      server,         # in_cred_server
      (err, out_creds) ->
        return handle_error(callback, err, ctx, null, ccache) if err
        callback undefined
  

spnego = (options, callback) ->
  options.ccname ?= ""
  if options.service_principal
    input_name_type = 'GSS_C_NT_USER_NAME'
    service = options.service_principal
  else if options.service_fqdn or options.hostbased_service
    input_name_type = 'GSS_C_NT_HOSTBASED_SERVICE'
    service = options.service_fqdn or options.hostbased_service
    service = "HTTP@#{service}" unless /.*[@]/.test service
  else return callback Error 'Missing option "service_principal" or "hostbased_service"'

  k.generate_spnego_token service, input_name_type, options.ccname, (err, token) ->
    return callback (if err is "" then undefined else Error err), token


module.exports =
  kinit: (options, callback) ->
    return kinit options, callback if typeof callback is 'function'
    return new Promise (resolve, reject) ->
      kinit options, (err, ccname) ->
        reject err if err
        resolve ccname

  spnego: (options, callback) ->
    return spnego options, callback if typeof callback is 'function'
    return new Promise (resolve, reject) ->
      spnego options, (err, token) ->
        reject err if err
        resolve token

  kdestroy: (options, callback) ->
    options ?= {}
    if typeof options is 'function'
      callback = options
      return kdestroy {}, callback
    else
      return kdestroy options, callback if typeof callback is 'function'
      return new Promise (resolve, reject) ->
        kdestroy options, (err) ->
          reject err if err
          resolve()

  kvno: (options, callback) ->
    return kvno options, callback if typeof callback is 'function'
    return new Promise (resolve, reject) ->
      kvno options, (err) ->
        reject err if err
        resolve()