/*
 * config.c - the platform-independent parts of the PuTTY
 * configuration box.
 */

#include <assert.h>
#include <stdlib.h>

#include "putty.h"
#include "dialog.h"
#include "storage.h"

#define PRINTER_DISABLED_STRING "无(禁用打印)" //"None (printing disabled)"

#define HOST_BOX_TITLE "主机名(或IP)" //"Host Name (or IP address)"
#define PORT_BOX_TITLE "端口" //Port

void conf_radiobutton_handler(union control *ctrl, void *dlg,
			      void *data, int event)
{
    int button;
    Conf *conf = (Conf *)data;

    /*
     * For a standard radio button set, the context parameter gives
     * the primary key (CONF_foo), and the extra data per button
     * gives the value the target field should take if that button
     * is the one selected.
     */
    if (event == EVENT_REFRESH) {
	int val = conf_get_int(conf, ctrl->radio.context.i);
	for (button = 0; button < ctrl->radio.nbuttons; button++)
	    if (val == ctrl->radio.buttondata[button].i)
		break;
	/* We expected that `break' to happen, in all circumstances. */
	assert(button < ctrl->radio.nbuttons);
	dlg_radiobutton_set(ctrl, dlg, button);
    } else if (event == EVENT_VALCHANGE) {
	button = dlg_radiobutton_get(ctrl, dlg);
	assert(button >= 0 && button < ctrl->radio.nbuttons);
	conf_set_int(conf, ctrl->radio.context.i,
		     ctrl->radio.buttondata[button].i);
    }
}

#define CHECKBOX_INVERT (1<<30)
void conf_checkbox_handler(union control *ctrl, void *dlg,
			   void *data, int event)
{
    int key, invert;
    Conf *conf = (Conf *)data;

    /*
     * For a standard checkbox, the context parameter gives the
     * primary key (CONF_foo), optionally ORed with CHECKBOX_INVERT.
     */
    key = ctrl->checkbox.context.i;
    if (key & CHECKBOX_INVERT) {
	key &= ~CHECKBOX_INVERT;
	invert = 1;
    } else
	invert = 0;

    /*
     * C lacks a logical XOR, so the following code uses the idiom
     * (!a ^ !b) to obtain the logical XOR of a and b. (That is, 1
     * iff exactly one of a and b is nonzero, otherwise 0.)
     */

    if (event == EVENT_REFRESH) {
	int val = conf_get_int(conf, key);
	dlg_checkbox_set(ctrl, dlg, (!val ^ !invert));
    } else if (event == EVENT_VALCHANGE) {
	conf_set_int(conf, key, !dlg_checkbox_get(ctrl,dlg) ^ !invert);
    }
}

void conf_editbox_handler(union control *ctrl, void *dlg,
			  void *data, int event)
{
    /*
     * The standard edit-box handler expects the main `context'
     * field to contain the primary key. The secondary `context2'
     * field indicates the type of this field:
     *
     *  - if context2 > 0, the field is a string.
     *  - if context2 == -1, the field is an int and the edit box
     *    is numeric.
     *  - if context2 < -1, the field is an int and the edit box is
     *    _floating_, and (-context2) gives the scale. (E.g. if
     *    context2 == -1000, then typing 1.2 into the box will set
     *    the field to 1200.)
     */
    int key = ctrl->editbox.context.i;
    int length = ctrl->editbox.context2.i;
    Conf *conf = (Conf *)data;

    if (length > 0) {
	if (event == EVENT_REFRESH) {
	    char *field = conf_get_str(conf, key);
	    dlg_editbox_set(ctrl, dlg, field);
	} else if (event == EVENT_VALCHANGE) {
	    char *field = dlg_editbox_get(ctrl, dlg);
	    conf_set_str(conf, key, field);
	    sfree(field);
	}
    } else if (length < 0) {
	if (event == EVENT_REFRESH) {
	    char str[80];
	    int value = conf_get_int(conf, key);
	    if (length == -1)
		sprintf(str, "%d", value);
	    else
		sprintf(str, "%g", (double)value / (double)(-length));
	    dlg_editbox_set(ctrl, dlg, str);
	} else if (event == EVENT_VALCHANGE) {
	    char *str = dlg_editbox_get(ctrl, dlg);
	    if (length == -1)
		conf_set_int(conf, key, atoi(str));
	    else
		conf_set_int(conf, key, (int)((-length) * atof(str)));
	    sfree(str);
	}
    }
}

void conf_filesel_handler(union control *ctrl, void *dlg,
			  void *data, int event)
{
    int key = ctrl->fileselect.context.i;
    Conf *conf = (Conf *)data;

    if (event == EVENT_REFRESH) {
	dlg_filesel_set(ctrl, dlg, conf_get_filename(conf, key));
    } else if (event == EVENT_VALCHANGE) {
	Filename *filename = dlg_filesel_get(ctrl, dlg);
	conf_set_filename(conf, key, filename);
        filename_free(filename);
    }
}

void conf_fontsel_handler(union control *ctrl, void *dlg,
			  void *data, int event)
{
    int key = ctrl->fontselect.context.i;
    Conf *conf = (Conf *)data;

    if (event == EVENT_REFRESH) {
	dlg_fontsel_set(ctrl, dlg, conf_get_fontspec(conf, key));
    } else if (event == EVENT_VALCHANGE) {
	FontSpec *fontspec = dlg_fontsel_get(ctrl, dlg);
	conf_set_fontspec(conf, key, fontspec);
        fontspec_free(fontspec);
    }
}

static void config_host_handler(union control *ctrl, void *dlg,
				void *data, int event)
{
    Conf *conf = (Conf *)data;

    /*
     * This function works just like the standard edit box handler,
     * only it has to choose the control's label and text from two
     * different places depending on the protocol.
     */
    if (event == EVENT_REFRESH) {
	if (conf_get_int(conf, CONF_protocol) == PROT_SERIAL) {
	    /*
	     * This label text is carefully chosen to contain an n,
	     * since that's the shortcut for the host name control.
	     */
	    dlg_label_change(ctrl, dlg, "Serial line");
	    dlg_editbox_set(ctrl, dlg, conf_get_str(conf, CONF_serline));
	} else {
	    dlg_label_change(ctrl, dlg, HOST_BOX_TITLE);
	    dlg_editbox_set(ctrl, dlg, conf_get_str(conf, CONF_host));
	}
    } else if (event == EVENT_VALCHANGE) {
	char *s = dlg_editbox_get(ctrl, dlg);
	if (conf_get_int(conf, CONF_protocol) == PROT_SERIAL)
	    conf_set_str(conf, CONF_serline, s);
	else
	    conf_set_str(conf, CONF_host, s);
	sfree(s);
    }
}

static void config_port_handler(union control *ctrl, void *dlg,
				void *data, int event)
{
    Conf *conf = (Conf *)data;
    char buf[80];

    /*
     * This function works similarly to the standard edit box handler,
     * only it has to choose the control's label and text from two
     * different places depending on the protocol.
     */
    if (event == EVENT_REFRESH) {
	if (conf_get_int(conf, CONF_protocol) == PROT_SERIAL) {
	    /*
	     * This label text is carefully chosen to contain a p,
	     * since that's the shortcut for the port control.
	     */
	    dlg_label_change(ctrl, dlg, "速度");//"Speed"
	    sprintf(buf, "%d", conf_get_int(conf, CONF_serspeed));
	} else {
	    dlg_label_change(ctrl, dlg, PORT_BOX_TITLE);
	    if (conf_get_int(conf, CONF_port) != 0)
		sprintf(buf, "%d", conf_get_int(conf, CONF_port));
	    else
		/* Display an (invalid) port of 0 as blank */
		buf[0] = '\0';
	}
	dlg_editbox_set(ctrl, dlg, buf);
    } else if (event == EVENT_VALCHANGE) {
	char *s = dlg_editbox_get(ctrl, dlg);
	int i = atoi(s);
	sfree(s);

	if (conf_get_int(conf, CONF_protocol) == PROT_SERIAL)
	    conf_set_int(conf, CONF_serspeed, i);
	else
	    conf_set_int(conf, CONF_port, i);
    }
}

struct hostport {
    union control *host, *port;
};

/*
 * We export this function so that platform-specific config
 * routines can use it to conveniently identify the protocol radio
 * buttons in order to add to them.
 */
void config_protocolbuttons_handler(union control *ctrl, void *dlg,
				    void *data, int event)
{
    int button;
    Conf *conf = (Conf *)data;
    struct hostport *hp = (struct hostport *)ctrl->radio.context.p;

    /*
     * This function works just like the standard radio-button
     * handler, except that it also has to change the setting of
     * the port box, and refresh both host and port boxes when. We
     * expect the context parameter to point at a hostport
     * structure giving the `union control's for both.
     */
    if (event == EVENT_REFRESH) {
	int protocol = conf_get_int(conf, CONF_protocol);
	for (button = 0; button < ctrl->radio.nbuttons; button++)
	    if (protocol == ctrl->radio.buttondata[button].i)
		break;
	/* We expected that `break' to happen, in all circumstances. */
	assert(button < ctrl->radio.nbuttons);
	dlg_radiobutton_set(ctrl, dlg, button);
    } else if (event == EVENT_VALCHANGE) {
	int oldproto = conf_get_int(conf, CONF_protocol);
	int newproto, port;

	button = dlg_radiobutton_get(ctrl, dlg);
	assert(button >= 0 && button < ctrl->radio.nbuttons);
	newproto = ctrl->radio.buttondata[button].i;
	conf_set_int(conf, CONF_protocol, newproto);

	if (oldproto != newproto) {
	    Backend *ob = backend_from_proto(oldproto);
	    Backend *nb = backend_from_proto(newproto);
	    assert(ob);
	    assert(nb);
	    /* Iff the user hasn't changed the port from the old protocol's
	     * default, update it with the new protocol's default.
	     * (This includes a "default" of 0, implying that there is no
	     * sensible default for that protocol; in this case it's
	     * displayed as a blank.)
	     * This helps with the common case of tabbing through the
	     * controls in order and setting a non-default port before
	     * getting to the protocol; we want that non-default port
	     * to be preserved. */
	    port = conf_get_int(conf, CONF_port);
	    if (port == ob->default_port)
		conf_set_int(conf, CONF_port, nb->default_port);
	}
	dlg_refresh(hp->host, dlg);
	dlg_refresh(hp->port, dlg);
    }
}

static void loggingbuttons_handler(union control *ctrl, void *dlg,
				   void *data, int event)
{
    int button;
    Conf *conf = (Conf *)data;
    /* This function works just like the standard radio-button handler,
     * but it has to fall back to "no logging" in situations where the
     * configured logging type isn't applicable.
     */
    if (event == EVENT_REFRESH) {
	int logtype = conf_get_int(conf, CONF_logtype);

        for (button = 0; button < ctrl->radio.nbuttons; button++)
            if (logtype == ctrl->radio.buttondata[button].i)
	        break;

	/* We fell off the end, so we lack the configured logging type */
	if (button == ctrl->radio.nbuttons) {
	    button = 0;
	    conf_set_int(conf, CONF_logtype, LGTYP_NONE);
	}
	dlg_radiobutton_set(ctrl, dlg, button);
    } else if (event == EVENT_VALCHANGE) {
        button = dlg_radiobutton_get(ctrl, dlg);
        assert(button >= 0 && button < ctrl->radio.nbuttons);
        conf_set_int(conf, CONF_logtype, ctrl->radio.buttondata[button].i);
    }
}

static void numeric_keypad_handler(union control *ctrl, void *dlg,
				   void *data, int event)
{
    int button;
    Conf *conf = (Conf *)data;
    /*
     * This function works much like the standard radio button
     * handler, but it has to handle two fields in Conf.
     */
    if (event == EVENT_REFRESH) {
	if (conf_get_int(conf, CONF_nethack_keypad))
	    button = 2;
	else if (conf_get_int(conf, CONF_app_keypad))
	    button = 1;
	else
	    button = 0;
	assert(button < ctrl->radio.nbuttons);
	dlg_radiobutton_set(ctrl, dlg, button);
    } else if (event == EVENT_VALCHANGE) {
	button = dlg_radiobutton_get(ctrl, dlg);
	assert(button >= 0 && button < ctrl->radio.nbuttons);
	if (button == 2) {
	    conf_set_int(conf, CONF_app_keypad, FALSE);
	    conf_set_int(conf, CONF_nethack_keypad, TRUE);
	} else {
	    conf_set_int(conf, CONF_app_keypad, (button != 0));
	    conf_set_int(conf, CONF_nethack_keypad, FALSE);
	}
    }
}

static void cipherlist_handler(union control *ctrl, void *dlg,
			       void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
	int i;

	static const struct { const char *s; int c; } ciphers[] = {
        { "ChaCha20 (SSH-2 only)",  CIPHER_CHACHA20 },
	    { "3DES",			        CIPHER_3DES },
	    { "Blowfish",		        CIPHER_BLOWFISH },
	    { "DES",			        CIPHER_DES },
	    { "AES (SSH-2 only)",	    CIPHER_AES },
	    { "Arcfour (SSH-2 only)",	CIPHER_ARCFOUR },
	    { "-- warn below here --",	CIPHER_WARN }
	};

	/* Set up the "selected ciphers" box. */
	/* (cipherlist assumed to contain all ciphers) */
	dlg_update_start(ctrl, dlg);
	dlg_listbox_clear(ctrl, dlg);
	for (i = 0; i < CIPHER_MAX; i++) {
	    int c = conf_get_int_int(conf, CONF_ssh_cipherlist, i);
	    int j;
	    const char *cstr = NULL;
	    for (j = 0; j < (sizeof ciphers) / (sizeof ciphers[0]); j++) {
		if (ciphers[j].c == c) {
		    cstr = ciphers[j].s;
		    break;
		}
	    }
	    dlg_listbox_addwithid(ctrl, dlg, cstr, c);
	}
	dlg_update_done(ctrl, dlg);

    } else if (event == EVENT_VALCHANGE) {
	int i;

	/* Update array to match the list box. */
	for (i=0; i < CIPHER_MAX; i++)
	    conf_set_int_int(conf, CONF_ssh_cipherlist, i,
			     dlg_listbox_getid(ctrl, dlg, i));
    }
}

#ifndef NO_GSSAPI
static void gsslist_handler(union control *ctrl, void *dlg,
			    void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
	int i;

	dlg_update_start(ctrl, dlg);
	dlg_listbox_clear(ctrl, dlg);
	for (i = 0; i < ngsslibs; i++) {
	    int id = conf_get_int_int(conf, CONF_ssh_gsslist, i);
	    assert(id >= 0 && id < ngsslibs);
	    dlg_listbox_addwithid(ctrl, dlg, gsslibnames[id], id);
	}
	dlg_update_done(ctrl, dlg);

    } else if (event == EVENT_VALCHANGE) {
	int i;

	/* Update array to match the list box. */
	for (i=0; i < ngsslibs; i++)
	    conf_set_int_int(conf, CONF_ssh_gsslist, i,
			     dlg_listbox_getid(ctrl, dlg, i));
    }
}
#endif

static void kexlist_handler(union control *ctrl, void *dlg,
			    void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
	int i;

	static const struct { const char *s; int k; } kexes[] = {
	    { "Diffie-Hellman group 1",		    KEX_DHGROUP1 },
	    { "Diffie-Hellman group 14",	    KEX_DHGROUP14 },
	    { "Diffie-Hellman group exchange",	KEX_DHGEX },
	    { "RSA-based key exchange", 	    KEX_RSA },
        { "ECDH key exchange",              KEX_ECDH },
	    { "-- warn below here --",		    KEX_WARN }
	};

	/* Set up the "kex preference" box. */
	/* (kexlist assumed to contain all algorithms) */
	dlg_update_start(ctrl, dlg);
	dlg_listbox_clear(ctrl, dlg);
	for (i = 0; i < KEX_MAX; i++) {
	    int k = conf_get_int_int(conf, CONF_ssh_kexlist, i);
	    int j;
	    const char *kstr = NULL;
	    for (j = 0; j < (sizeof kexes) / (sizeof kexes[0]); j++) {
		if (kexes[j].k == k) {
		    kstr = kexes[j].s;
		    break;
		}
	    }
	    dlg_listbox_addwithid(ctrl, dlg, kstr, k);
	}
	dlg_update_done(ctrl, dlg);

    } else if (event == EVENT_VALCHANGE) {
	int i;

	/* Update array to match the list box. */
	for (i=0; i < KEX_MAX; i++)
	    conf_set_int_int(conf, CONF_ssh_kexlist, i,
			     dlg_listbox_getid(ctrl, dlg, i));
    }
}

static void hklist_handler(union control *ctrl, void *dlg,
                            void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
        int i;

        static const struct { const char *s; int k; } hks[] = {
            { "Ed25519",               HK_ED25519 },
            { "ECDSA",                 HK_ECDSA },
            { "DSA",                   HK_DSA },
            { "RSA",                   HK_RSA },
            { "-- warn below here --", HK_WARN }
        };

        /* Set up the "host key preference" box. */
        /* (hklist assumed to contain all algorithms) */
        dlg_update_start(ctrl, dlg);
        dlg_listbox_clear(ctrl, dlg);
        for (i = 0; i < HK_MAX; i++) {
            int k = conf_get_int_int(conf, CONF_ssh_hklist, i);
            int j;
            const char *kstr = NULL;
            for (j = 0; j < lenof(hks); j++) {
                if (hks[j].k == k) {
                    kstr = hks[j].s;
                    break;
                }
            }
            dlg_listbox_addwithid(ctrl, dlg, kstr, k);
        }
        dlg_update_done(ctrl, dlg);

    } else if (event == EVENT_VALCHANGE) {
        int i;

        /* Update array to match the list box. */
        for (i=0; i < HK_MAX; i++)
            conf_set_int_int(conf, CONF_ssh_hklist, i,
                             dlg_listbox_getid(ctrl, dlg, i));
    }
}

static void printerbox_handler(union control *ctrl, void *dlg,
			       void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
	int nprinters, i;
	printer_enum *pe;
	const char *printer;

	dlg_update_start(ctrl, dlg);
	/*
	 * Some backends may wish to disable the drop-down list on
	 * this edit box. Be prepared for this.
	 */
	if (ctrl->editbox.has_list) {
	    dlg_listbox_clear(ctrl, dlg);
	    dlg_listbox_add(ctrl, dlg, PRINTER_DISABLED_STRING);
	    pe = printer_start_enum(&nprinters);
	    for (i = 0; i < nprinters; i++)
		dlg_listbox_add(ctrl, dlg, printer_get_name(pe, i));
	    printer_finish_enum(pe);
	}
	printer = conf_get_str(conf, CONF_printer);
	if (!printer)
	    printer = PRINTER_DISABLED_STRING;
	dlg_editbox_set(ctrl, dlg, printer);
	dlg_update_done(ctrl, dlg);
    } else if (event == EVENT_VALCHANGE) {
	char *printer = dlg_editbox_get(ctrl, dlg);
	if (!strcmp(printer, PRINTER_DISABLED_STRING))
	    printer[0] = '\0';
	conf_set_str(conf, CONF_printer, printer);
	sfree(printer);
    }
}

static void codepage_handler(union control *ctrl, void *dlg,
			     void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
	int i;
	const char *cp, *thiscp;
	dlg_update_start(ctrl, dlg);
	thiscp = cp_name(decode_codepage(conf_get_str(conf,
						      CONF_line_codepage)));
	dlg_listbox_clear(ctrl, dlg);
	for (i = 0; (cp = cp_enumerate(i)) != NULL; i++)
	    dlg_listbox_add(ctrl, dlg, cp);
	dlg_editbox_set(ctrl, dlg, thiscp);
	conf_set_str(conf, CONF_line_codepage, thiscp);
	dlg_update_done(ctrl, dlg);
    } else if (event == EVENT_VALCHANGE) {
	char *codepage = dlg_editbox_get(ctrl, dlg);
	conf_set_str(conf, CONF_line_codepage,
		     cp_name(decode_codepage(codepage)));
	sfree(codepage);
    }
}

static void sshbug_handler(union control *ctrl, void *dlg,
			   void *data, int event)
{
    Conf *conf = (Conf *)data;
    if (event == EVENT_REFRESH) {
        /*
         * We must fetch the previously configured value from the Conf
         * before we start modifying the drop-down list, otherwise the
         * spurious SELCHANGE we trigger in the process will overwrite
         * the value we wanted to keep.
         */
        int oldconf = conf_get_int(conf, ctrl->listbox.context.i);
	dlg_update_start(ctrl, dlg);
	dlg_listbox_clear(ctrl, dlg);
	dlg_listbox_addwithid(ctrl, dlg, "自动", AUTO); //"Auto"
	dlg_listbox_addwithid(ctrl, dlg, "关", FORCE_OFF); //"Off"
	dlg_listbox_addwithid(ctrl, dlg, "开", FORCE_ON); //"On"
	switch (oldconf) {
	  case AUTO:      dlg_listbox_select(ctrl, dlg, 0); break;
	  case FORCE_OFF: dlg_listbox_select(ctrl, dlg, 1); break;
	  case FORCE_ON:  dlg_listbox_select(ctrl, dlg, 2); break;
	}
	dlg_update_done(ctrl, dlg);
    } else if (event == EVENT_SELCHANGE) {
	int i = dlg_listbox_index(ctrl, dlg);
	if (i < 0)
	    i = AUTO;
	else
	    i = dlg_listbox_getid(ctrl, dlg, i);
	conf_set_int(conf, ctrl->listbox.context.i, i);
    }
}

struct sessionsaver_data {
    union control *editbox, *listbox, *loadbutton, *savebutton, *delbutton;
    union control *okbutton, *cancelbutton;
    struct sesslist sesslist;
    int midsession;
    char *savedsession;     /* the current contents of ssd->editbox */
};

static void sessionsaver_data_free(void *ssdv)
{
    struct sessionsaver_data *ssd = (struct sessionsaver_data *)ssdv;
    get_sesslist(&ssd->sesslist, FALSE);
    sfree(ssd->savedsession);
    sfree(ssd);
}

/* 
 * Helper function to load the session selected in the list box, if
 * any, as this is done in more than one place below. Returns 0 for
 * failure.
 */
static int load_selected_session(struct sessionsaver_data *ssd,
				 void *dlg, Conf *conf, int *maybe_launch)
{
    int i = dlg_listbox_index(ssd->listbox, dlg);
    int isdef;
    if (i < 0) {
	dlg_beep(dlg);
	return 0;
    }
    isdef = !strcmp(ssd->sesslist.sessions[i], "Default Settings"); //"Default Settings"
    load_settings(ssd->sesslist.sessions[i], conf);
    sfree(ssd->savedsession);
    ssd->savedsession = dupstr(isdef ? "" : ssd->sesslist.sessions[i]);
    if (maybe_launch)
        *maybe_launch = !isdef;
    dlg_refresh(NULL, dlg);
    /* Restore the selection, which might have been clobbered by
     * changing the value of the edit box. */
    dlg_listbox_select(ssd->listbox, dlg, i);
    return 1;
}

static void sessionsaver_handler(union control *ctrl, void *dlg,
				 void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct sessionsaver_data *ssd =
	(struct sessionsaver_data *)ctrl->generic.context.p;

    if (event == EVENT_REFRESH) {
	if (ctrl == ssd->editbox) {
	    dlg_editbox_set(ctrl, dlg, ssd->savedsession);
	} else if (ctrl == ssd->listbox) {
	    int i;
	    dlg_update_start(ctrl, dlg);
	    dlg_listbox_clear(ctrl, dlg);
	    for (i = 0; i < ssd->sesslist.nsessions; i++)
		dlg_listbox_add(ctrl, dlg, ssd->sesslist.sessions[i]);
	    dlg_update_done(ctrl, dlg);
	}
    } else if (event == EVENT_VALCHANGE) {
        int top, bottom, halfway, i;
	if (ctrl == ssd->editbox) {
            sfree(ssd->savedsession);
            ssd->savedsession = dlg_editbox_get(ctrl, dlg);
	    top = ssd->sesslist.nsessions;
	    bottom = -1;
	    while (top-bottom > 1) {
	        halfway = (top+bottom)/2;
	        i = strcmp(ssd->savedsession, ssd->sesslist.sessions[halfway]);
	        if (i <= 0 ) {
		    top = halfway;
	        } else {
		    bottom = halfway;
	        }
	    }
	    if (top == ssd->sesslist.nsessions) {
	        top -= 1;
	    }
	    dlg_listbox_select(ssd->listbox, dlg, top);
	}
    } else if (event == EVENT_ACTION) {
	int mbl = FALSE;
	if (!ssd->midsession &&
	    (ctrl == ssd->listbox ||
	     (ssd->loadbutton && ctrl == ssd->loadbutton))) {
	    /*
	     * The user has double-clicked a session, or hit Load.
	     * We must load the selected session, and then
	     * terminate the configuration dialog _if_ there was a
	     * double-click on the list box _and_ that session
	     * contains a hostname.
	     */
	    if (load_selected_session(ssd, dlg, conf, &mbl) &&
		(mbl && ctrl == ssd->listbox && conf_launchable(conf))) {
		dlg_end(dlg, 1);       /* it's all over, and succeeded */
	    }
	} else if (ctrl == ssd->savebutton) {
	    int isdef = !strcmp(ssd->savedsession, "Default Settings");//"Default Settings"
	    if (!ssd->savedsession[0]) {
		int i = dlg_listbox_index(ssd->listbox, dlg);
		if (i < 0) {
		    dlg_beep(dlg);
		    return;
		}
		isdef = !strcmp(ssd->sesslist.sessions[i], "Default Settings");//"Default Settings"
                sfree(ssd->savedsession);
                ssd->savedsession = dupstr(isdef ? "" :
                                           ssd->sesslist.sessions[i]);
	    }
            {
                char *errmsg = save_settings(ssd->savedsession, conf);
                if (errmsg) {
                    dlg_error_msg(dlg, errmsg);
                    sfree(errmsg);
                }
            }
	    get_sesslist(&ssd->sesslist, FALSE);
	    get_sesslist(&ssd->sesslist, TRUE);
	    dlg_refresh(ssd->editbox, dlg);
	    dlg_refresh(ssd->listbox, dlg);
	} else if (!ssd->midsession &&
		   ssd->delbutton && ctrl == ssd->delbutton) {
	    int i = dlg_listbox_index(ssd->listbox, dlg);
	    if (i <= 0) {
		dlg_beep(dlg);
	    } else {
		del_settings(ssd->sesslist.sessions[i]);
		get_sesslist(&ssd->sesslist, FALSE);
		get_sesslist(&ssd->sesslist, TRUE);
		dlg_refresh(ssd->listbox, dlg);
	    }
	} else if (ctrl == ssd->okbutton) {
            if (ssd->midsession) {
                /* In a mid-session Change Settings, Apply is always OK. */
		dlg_end(dlg, 1);
                return;
            }
	    /*
	     * Annoying special case. If the `Open' button is
	     * pressed while no host name is currently set, _and_
	     * the session list previously had the focus, _and_
	     * there was a session selected in that which had a
	     * valid host name in it, then load it and go.
	     */
	    if (dlg_last_focused(ctrl, dlg) == ssd->listbox &&
		!conf_launchable(conf)) {
		Conf *conf2 = conf_new();
		int mbl = FALSE;
		if (!load_selected_session(ssd, dlg, conf2, &mbl)) {
		    dlg_beep(dlg);
		    conf_free(conf2);
		    return;
		}
		/* If at this point we have a valid session, go! */
		if (mbl && conf_launchable(conf2)) {
		    conf_copy_into(conf, conf2);
		    dlg_end(dlg, 1);
		} else
		    dlg_beep(dlg);

		conf_free(conf2);
                return;
	    }

	    /*
	     * Otherwise, do the normal thing: if we have a valid
	     * session, get going.
	     */
	    if (conf_launchable(conf)) {
		dlg_end(dlg, 1);
	    } else
		dlg_beep(dlg);
	} else if (ctrl == ssd->cancelbutton) {
	    dlg_end(dlg, 0);
	}
    }
}

struct charclass_data {
    union control *listbox, *editbox, *button;
};

static void charclass_handler(union control *ctrl, void *dlg,
			      void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct charclass_data *ccd =
	(struct charclass_data *)ctrl->generic.context.p;

    if (event == EVENT_REFRESH) {
	if (ctrl == ccd->listbox) {
	    int i;
	    dlg_update_start(ctrl, dlg);
	    dlg_listbox_clear(ctrl, dlg);
	    for (i = 0; i < 128; i++) {
		char str[100];
		sprintf(str, "%d\t(0x%02X)\t%c\t%d", i, i,
			(i >= 0x21 && i != 0x7F) ? i : ' ',
			conf_get_int_int(conf, CONF_wordness, i));
		dlg_listbox_add(ctrl, dlg, str);
	    }
	    dlg_update_done(ctrl, dlg);
	}
    } else if (event == EVENT_ACTION) {
	if (ctrl == ccd->button) {
	    char *str;
	    int i, n;
	    str = dlg_editbox_get(ccd->editbox, dlg);
	    n = atoi(str);
	    sfree(str);
	    for (i = 0; i < 128; i++) {
		if (dlg_listbox_issel(ccd->listbox, dlg, i))
		    conf_set_int_int(conf, CONF_wordness, i, n);
	    }
	    dlg_refresh(ccd->listbox, dlg);
	}
    }
}

struct colour_data {
    union control *listbox, *redit, *gedit, *bedit, *button;
};

static const char *const colours[] = {
    "Default Foreground", "Default Bold Foreground",
    "Default Background", "Default Bold Background",
    "Cursor Text", "Cursor Colour",
    "ANSI Black", "ANSI Black Bold",
    "ANSI Red", "ANSI Red Bold",
    "ANSI Green", "ANSI Green Bold",
    "ANSI Yellow", "ANSI Yellow Bold",
    "ANSI Blue", "ANSI Blue Bold",
    "ANSI Magenta", "ANSI Magenta Bold",
    "ANSI Cyan", "ANSI Cyan Bold",
    "ANSI White", "ANSI White Bold"
};

static void colour_handler(union control *ctrl, void *dlg,
			    void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct colour_data *cd =
	(struct colour_data *)ctrl->generic.context.p;
    int update = FALSE, clear = FALSE, r, g, b;

    if (event == EVENT_REFRESH) {
	if (ctrl == cd->listbox) {
	    int i;
	    dlg_update_start(ctrl, dlg);
	    dlg_listbox_clear(ctrl, dlg);
	    for (i = 0; i < lenof(colours); i++)
		dlg_listbox_add(ctrl, dlg, colours[i]);
	    dlg_update_done(ctrl, dlg);
	    clear = TRUE;
	    update = TRUE;
	}
    } else if (event == EVENT_SELCHANGE) {
	if (ctrl == cd->listbox) {
	    /* The user has selected a colour. Update the RGB text. */
	    int i = dlg_listbox_index(ctrl, dlg);
	    if (i < 0) {
		clear = TRUE;
	    } else {
		clear = FALSE;
		r = conf_get_int_int(conf, CONF_colours, i*3+0);
		g = conf_get_int_int(conf, CONF_colours, i*3+1);
		b = conf_get_int_int(conf, CONF_colours, i*3+2);
	    }
	    update = TRUE;
	}
    } else if (event == EVENT_VALCHANGE) {
	if (ctrl == cd->redit || ctrl == cd->gedit || ctrl == cd->bedit) {
	    /* The user has changed the colour using the edit boxes. */
	    char *str;
	    int i, cval;

	    str = dlg_editbox_get(ctrl, dlg);
	    cval = atoi(str);
	    sfree(str);
	    if (cval > 255) cval = 255;
	    if (cval < 0)   cval = 0;

	    i = dlg_listbox_index(cd->listbox, dlg);
	    if (i >= 0) {
		if (ctrl == cd->redit)
		    conf_set_int_int(conf, CONF_colours, i*3+0, cval);
		else if (ctrl == cd->gedit)
		    conf_set_int_int(conf, CONF_colours, i*3+1, cval);
		else if (ctrl == cd->bedit)
		    conf_set_int_int(conf, CONF_colours, i*3+2, cval);
	    }
	}
    } else if (event == EVENT_ACTION) {
	if (ctrl == cd->button) {
	    int i = dlg_listbox_index(cd->listbox, dlg);
	    if (i < 0) {
		dlg_beep(dlg);
		return;
	    }
	    /*
	     * Start a colour selector, which will send us an
	     * EVENT_CALLBACK when it's finished and allow us to
	     * pick up the results.
	     */
	    dlg_coloursel_start(ctrl, dlg,
				conf_get_int_int(conf, CONF_colours, i*3+0),
				conf_get_int_int(conf, CONF_colours, i*3+1),
				conf_get_int_int(conf, CONF_colours, i*3+2));
	}
    } else if (event == EVENT_CALLBACK) {
	if (ctrl == cd->button) {
	    int i = dlg_listbox_index(cd->listbox, dlg);
	    /*
	     * Collect the results of the colour selector. Will
	     * return nonzero on success, or zero if the colour
	     * selector did nothing (user hit Cancel, for example).
	     */
	    if (dlg_coloursel_results(ctrl, dlg, &r, &g, &b)) {
		conf_set_int_int(conf, CONF_colours, i*3+0, r);
		conf_set_int_int(conf, CONF_colours, i*3+1, g);
		conf_set_int_int(conf, CONF_colours, i*3+2, b);
		clear = FALSE;
		update = TRUE;
	    }
	}
    }

    if (update) {
	if (clear) {
	    dlg_editbox_set(cd->redit, dlg, "");
	    dlg_editbox_set(cd->gedit, dlg, "");
	    dlg_editbox_set(cd->bedit, dlg, "");
	} else {
	    char buf[40];
	    sprintf(buf, "%d", r); dlg_editbox_set(cd->redit, dlg, buf);
	    sprintf(buf, "%d", g); dlg_editbox_set(cd->gedit, dlg, buf);
	    sprintf(buf, "%d", b); dlg_editbox_set(cd->bedit, dlg, buf);
	}
    }
}

struct ttymodes_data {
    union control *valradio, *valbox, *setbutton, *listbox;
};

static void ttymodes_handler(union control *ctrl, void *dlg,
			     void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct ttymodes_data *td =
	(struct ttymodes_data *)ctrl->generic.context.p;

    if (event == EVENT_REFRESH) {
	if (ctrl == td->listbox) {
	    char *key, *val;
	    dlg_update_start(ctrl, dlg);
	    dlg_listbox_clear(ctrl, dlg);
	    for (val = conf_get_str_strs(conf, CONF_ttymodes, NULL, &key);
		 val != NULL;
		 val = conf_get_str_strs(conf, CONF_ttymodes, key, &key)) {
		char *disp = dupprintf("%s\t%s", key,
				       (val[0] == 'A') ? "(自动)" : //"(auto)"
				       ((val[0] == 'N') ? "(不发送)" //"(don't send)"
							: val+1));
		dlg_listbox_add(ctrl, dlg, disp);
		sfree(disp);
	    }
	    dlg_update_done(ctrl, dlg);
	} else if (ctrl == td->valradio) {
	    dlg_radiobutton_set(ctrl, dlg, 0);
	}
    } else if (event == EVENT_SELCHANGE) {
	if (ctrl == td->listbox) {
	    int ind = dlg_listbox_index(td->listbox, dlg);
	    char *val;
	    if (ind < 0) {
		return; /* no item selected */
	    }
	    val = conf_get_str_str(conf, CONF_ttymodes,
				   conf_get_str_nthstrkey(conf, CONF_ttymodes,
							  ind));
	    assert(val != NULL);
	    /* Do this first to defuse side-effects on radio buttons: */
	    dlg_editbox_set(td->valbox, dlg, val+1);
	    dlg_radiobutton_set(td->valradio, dlg,
				val[0] == 'A' ? 0 : (val[0] == 'N' ? 1 : 2));
	}
    } else if (event == EVENT_VALCHANGE) {
	if (ctrl == td->valbox) {
	    /* If they're editing the text box, we assume they want its
	     * value to be used. */
	    dlg_radiobutton_set(td->valradio, dlg, 2);
	}
    } else if (event == EVENT_ACTION) {
	if (ctrl == td->setbutton) {
	    int ind = dlg_listbox_index(td->listbox, dlg);
	    const char *key;
	    char *str, *val;
	    char type;

	    {
		const char *types = "ANV";
		int button = dlg_radiobutton_get(td->valradio, dlg);
		assert(button >= 0 && button < lenof(types));
		type = types[button];
	    }

	    /* Construct new entry */
	    if (ind >= 0) {
		key = conf_get_str_nthstrkey(conf, CONF_ttymodes, ind);
		str = (type == 'V' ? dlg_editbox_get(td->valbox, dlg)
				   : dupstr(""));
		val = dupprintf("%c%s", type, str);
		sfree(str);
		conf_set_str_str(conf, CONF_ttymodes, key, val);
		sfree(val);
		dlg_refresh(td->listbox, dlg);
		dlg_listbox_select(td->listbox, dlg, ind);
	    } else {
		/* Not a multisel listbox, so this means nothing selected */
		dlg_beep(dlg);
	    }
	}
    }
}

struct environ_data {
    union control *varbox, *valbox, *addbutton, *rembutton, *listbox;
};

static void environ_handler(union control *ctrl, void *dlg,
			    void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct environ_data *ed =
	(struct environ_data *)ctrl->generic.context.p;

    if (event == EVENT_REFRESH) {
	if (ctrl == ed->listbox) {
	    char *key, *val;
	    dlg_update_start(ctrl, dlg);
	    dlg_listbox_clear(ctrl, dlg);
	    for (val = conf_get_str_strs(conf, CONF_environmt, NULL, &key);
		 val != NULL;
		 val = conf_get_str_strs(conf, CONF_environmt, key, &key)) {
		char *p = dupprintf("%s\t%s", key, val);
		dlg_listbox_add(ctrl, dlg, p);
		sfree(p);
	    }
	    dlg_update_done(ctrl, dlg);
	}
    } else if (event == EVENT_ACTION) {
	if (ctrl == ed->addbutton) {
	    char *key, *val, *str;
	    key = dlg_editbox_get(ed->varbox, dlg);
	    if (!*key) {
		sfree(key);
		dlg_beep(dlg);
		return;
	    }
	    val = dlg_editbox_get(ed->valbox, dlg);
	    if (!*val) {
		sfree(key);
		sfree(val);
		dlg_beep(dlg);
		return;
	    }
	    conf_set_str_str(conf, CONF_environmt, key, val);
	    str = dupcat(key, "\t", val, NULL);
	    dlg_editbox_set(ed->varbox, dlg, "");
	    dlg_editbox_set(ed->valbox, dlg, "");
	    sfree(str);
	    sfree(key);
	    sfree(val);
	    dlg_refresh(ed->listbox, dlg);
	} else if (ctrl == ed->rembutton) {
	    int i = dlg_listbox_index(ed->listbox, dlg);
	    if (i < 0) {
		dlg_beep(dlg);
	    } else {
		char *key, *val;

		key = conf_get_str_nthstrkey(conf, CONF_environmt, i);
		if (key) {
		    /* Populate controls with the entry we're about to delete
		     * for ease of editing */
		    val = conf_get_str_str(conf, CONF_environmt, key);
		    dlg_editbox_set(ed->varbox, dlg, key);
		    dlg_editbox_set(ed->valbox, dlg, val);
		    /* And delete it */
		    conf_del_str_str(conf, CONF_environmt, key);
		}
	    }
	    dlg_refresh(ed->listbox, dlg);
	}
    }
}

struct portfwd_data {
    union control *addbutton, *rembutton, *listbox;
    union control *sourcebox, *destbox, *direction;
#ifndef NO_IPV6
    union control *addressfamily;
#endif
};

static void portfwd_handler(union control *ctrl, void *dlg,
			    void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct portfwd_data *pfd =
	(struct portfwd_data *)ctrl->generic.context.p;

    if (event == EVENT_REFRESH) {
	if (ctrl == pfd->listbox) {
	    char *key, *val;
	    dlg_update_start(ctrl, dlg);
	    dlg_listbox_clear(ctrl, dlg);
	    for (val = conf_get_str_strs(conf, CONF_portfwd, NULL, &key);
		 val != NULL;
		 val = conf_get_str_strs(conf, CONF_portfwd, key, &key)) {
		char *p;
        if (!strcmp(val, "D")) {
            char *L;
            /*
            * A dynamic forwarding is stored as L12345=D or
            * 6L12345=D (since it's mutually exclusive with
            * L12345=anything else), but displayed as D12345
            * to match the fiction that 'Local', 'Remote' and
            * 'Dynamic' are three distinct modes and also to
            * align with OpenSSH's command line option syntax
            * that people will already be used to. So, for
            * display purposes, find the L in the key string
            * and turn it into a D.
            */
            p = dupprintf("%s\t", key);
            L = strchr(p, 'L');
            if (L) *L = 'D';
        } else
            p = dupprintf("%s\t%s", key, val);
		dlg_listbox_add(ctrl, dlg, p);
		sfree(p);
	    }
	    dlg_update_done(ctrl, dlg);
	} else if (ctrl == pfd->direction) {
	    /*
	     * Default is Local.
	     */
	    dlg_radiobutton_set(ctrl, dlg, 0);
#ifndef NO_IPV6
	} else if (ctrl == pfd->addressfamily) {
	    dlg_radiobutton_set(ctrl, dlg, 0);
#endif
	}
    } else if (event == EVENT_ACTION) {
	if (ctrl == pfd->addbutton) {
	    const char *family, *type;
            char *src, *key, *val;
	    int whichbutton;

#ifndef NO_IPV6
	    whichbutton = dlg_radiobutton_get(pfd->addressfamily, dlg);
	    if (whichbutton == 1)
		family = "4";
	    else if (whichbutton == 2)
		family = "6";
	    else
#endif
		family = "";

	    whichbutton = dlg_radiobutton_get(pfd->direction, dlg);
	    if (whichbutton == 0)
		type = "L";
	    else if (whichbutton == 1)
		type = "R";
	    else
		type = "D";

	    src = dlg_editbox_get(pfd->sourcebox, dlg);
	    if (!*src) {
		dlg_error_msg(dlg, "您需要指定源端口号");//"You need to specify a source port number"
		sfree(src);
		return;
	    }
	    if (*type != 'D') {
		val = dlg_editbox_get(pfd->destbox, dlg);
		if (!*val || !host_strchr(val, ':')) {
		    dlg_error_msg(dlg,
				  "您需要在表单\"host.name:port\"中指定目的地址");//"You need to specify a destination address\n""in the form \"host.name:port\""
		    sfree(src);
		    sfree(val);
		    return;
		}
	    } else {
                type = "L";
		val = dupstr("D");     /* special case */
            }

	    key = dupcat(family, type, src, NULL);
	    sfree(src);

	    if (conf_get_str_str_opt(conf, CONF_portfwd, key)) {
		dlg_error_msg(dlg, "指定的转发已经存在");//"Specified forwarding already exists"
	    } else {
		conf_set_str_str(conf, CONF_portfwd, key, val);
	    }

	    sfree(key);
	    sfree(val);
	    dlg_refresh(pfd->listbox, dlg);
	} else if (ctrl == pfd->rembutton) {
	    int i = dlg_listbox_index(pfd->listbox, dlg);
	    if (i < 0) {
		dlg_beep(dlg);
	    } else {
		char *key, *p;
                const char *val;

		key = conf_get_str_nthstrkey(conf, CONF_portfwd, i);
		if (key) {
		    static const char *const afs = "A46";
		    static const char *const dirs = "LRD";
		    char *afp;
		    int dir;
#ifndef NO_IPV6
		    int idx;
#endif

		    /* Populate controls with the entry we're about to delete
		     * for ease of editing */
		    p = key;

		    afp = strchr(afs, *p);
#ifndef NO_IPV6
		    idx = afp ? afp-afs : 0;
#endif
		    if (afp)
			p++;
#ifndef NO_IPV6
		    dlg_radiobutton_set(pfd->addressfamily, dlg, idx);
#endif

		    dir = *p;

                    val = conf_get_str_str(conf, CONF_portfwd, key);
		    if (!strcmp(val, "D")) {
                        dir = 'D';
			val = "";
		    }

		    dlg_radiobutton_set(pfd->direction, dlg,
					strchr(dirs, dir) - dirs);
		    p++;

		    dlg_editbox_set(pfd->sourcebox, dlg, p);
		    dlg_editbox_set(pfd->destbox, dlg, val);
		    /* And delete it */
		    conf_del_str_str(conf, CONF_portfwd, key);
		}
	    }
	    dlg_refresh(pfd->listbox, dlg);
	}
    }
}

struct manual_hostkey_data {
    union control *addbutton, *rembutton, *listbox, *keybox;
};

static void manual_hostkey_handler(union control *ctrl, void *dlg,
                                   void *data, int event)
{
    Conf *conf = (Conf *)data;
    struct manual_hostkey_data *mh =
	(struct manual_hostkey_data *)ctrl->generic.context.p;

    if (event == EVENT_REFRESH) {
	if (ctrl == mh->listbox) {
	    char *key, *val;
	    dlg_update_start(ctrl, dlg);
	    dlg_listbox_clear(ctrl, dlg);
	    for (val = conf_get_str_strs(conf, CONF_ssh_manual_hostkeys,
                                         NULL, &key);
		 val != NULL;
		 val = conf_get_str_strs(conf, CONF_ssh_manual_hostkeys,
                                         key, &key)) {
		dlg_listbox_add(ctrl, dlg, key);
	    }
	    dlg_update_done(ctrl, dlg);
	}
    } else if (event == EVENT_ACTION) {
	if (ctrl == mh->addbutton) {
	    char *key;

	    key = dlg_editbox_get(mh->keybox, dlg);
	    if (!*key) {
		dlg_error_msg(dlg, "您需要指定一个主机密钥或指纹");//"You need to specify a host key or ""fingerprint"
		sfree(key);
		return;
	    }

            if (!validate_manual_hostkey(key)) {
		dlg_error_msg(dlg, "主机密钥不是有效格式");//"Host key is not in a valid format"
            } else if (conf_get_str_str_opt(conf, CONF_ssh_manual_hostkeys,
                                            key)) {
		dlg_error_msg(dlg, "指定的主机密钥已经列出");//"Specified host key is already listed"
	    } else {
		conf_set_str_str(conf, CONF_ssh_manual_hostkeys, key, "");
	    }

	    sfree(key);
	    dlg_refresh(mh->listbox, dlg);
	} else if (ctrl == mh->rembutton) {
	    int i = dlg_listbox_index(mh->listbox, dlg);
	    if (i < 0) {
		dlg_beep(dlg);
	    } else {
		char *key;

		key = conf_get_str_nthstrkey(conf, CONF_ssh_manual_hostkeys, i);
		if (key) {
		    dlg_editbox_set(mh->keybox, dlg, key);
		    /* And delete it */
		    conf_del_str_str(conf, CONF_ssh_manual_hostkeys, key);
		}
	    }
	    dlg_refresh(mh->listbox, dlg);
	}
    }
}

void setup_config_box(struct controlbox *b, int midsession,
		      int protocol, int protcfginfo)
{
    struct controlset *s;
    struct sessionsaver_data *ssd;
    struct charclass_data *ccd;
    struct colour_data *cd;
    struct ttymodes_data *td;
    struct environ_data *ed;
    struct portfwd_data *pfd;
    struct manual_hostkey_data *mh;
    union control *c;
    char *str;

    ssd = (struct sessionsaver_data *)
	ctrl_alloc_with_free(b, sizeof(struct sessionsaver_data),
                             sessionsaver_data_free);
    memset(ssd, 0, sizeof(*ssd));
    ssd->savedsession = dupstr("");
    ssd->midsession = midsession;

    /*
     * The standard panel that appears at the bottom of all panels:
     * Open, Cancel, Apply etc.
     */
    s = ctrl_getset(b, "", "", "");
    ctrl_columns(s, 5, 20, 20, 20, 20, 20);
    ssd->okbutton = ctrl_pushbutton(s,
				    (midsession ? "应用" : "打开"),//"Apply" : "Open"
				    (char)(midsession ? 'a' : 'o'),
				    HELPCTX(no_help),
				    sessionsaver_handler, P(ssd));
    ssd->okbutton->button.isdefault = TRUE;
    ssd->okbutton->generic.column = 3;
    ssd->cancelbutton = ctrl_pushbutton(s, "取消", 'c', HELPCTX(no_help),//"Cancel"
					sessionsaver_handler, P(ssd));
    ssd->cancelbutton->button.iscancel = TRUE;
    ssd->cancelbutton->generic.column = 4;
    /* We carefully don't close the 5-column part, so that platform-
     * specific add-ons can put extra buttons alongside Open and Cancel. */

    /*
     * The Session panel.
     */
    str = dupprintf("%s会话的基本选项", appname);//"Basic options for your %s session"
    ctrl_settitle(b, "Session", str);
    sfree(str);

    if (!midsession) {
	struct hostport *hp = (struct hostport *)
	    ctrl_alloc(b, sizeof(struct hostport));

	s = ctrl_getset(b, "Session", "hostport",
			"指定要连接的目标");//"Specify the destination you want to connect"
	ctrl_columns(s, 2, 75, 25);
	c = ctrl_editbox(s, HOST_BOX_TITLE, 'n', 100,
			 HELPCTX(session_hostname),
			 config_host_handler, I(0), I(0));
	c->generic.column = 0;
	hp->host = c;
	c = ctrl_editbox(s, PORT_BOX_TITLE, 'p', 100,
			 HELPCTX(session_hostname),
			 config_port_handler, I(0), I(0));
	c->generic.column = 1;
	hp->port = c;
	ctrl_columns(s, 1, 100);

	if (!backend_from_proto(PROT_SSH)) {
	    ctrl_radiobuttons(s, "连接类型:", NO_SHORTCUT, 3,//"Connection type:"
			      HELPCTX(session_hostname),
			      config_protocolbuttons_handler, P(hp),
			      "Raw", 'w', I(PROT_RAW),//"Raw"
			      "Telnet", 't', I(PROT_TELNET),//"Telnet"
			      "Rlogin", 'i', I(PROT_RLOGIN),//"Rlogin"
			      NULL);
	} else {
	    ctrl_radiobuttons(s, "连接类型:", NO_SHORTCUT, 4,//"Connection type:"
			      HELPCTX(session_hostname),
			      config_protocolbuttons_handler, P(hp),
			      "Raw", 'w', I(PROT_RAW),//"Raw"
			      "Telnet", 't', I(PROT_TELNET),//"Telnet"
			      "Rlogin", 'i', I(PROT_RLOGIN),//"Rlogin"
			      "SSH", 's', I(PROT_SSH),//"SSH"
			      NULL);
	}
    }

    /*
     * The Load/Save panel is available even in mid-session.
     */
    s = ctrl_getset(b, "Session", "savedsessions",
		    midsession ? "保存当前会话设置" ://"Save the current session settings"
		    "加载,保存或删除存储的会话");//"Load, save or delete a stored session"
    ctrl_columns(s, 2, 75, 25);
    get_sesslist(&ssd->sesslist, TRUE);
    ssd->editbox = ctrl_editbox(s, "保存会话", 'e', 100,//"Saved Sessions"
				HELPCTX(session_saved),
				sessionsaver_handler, P(ssd), P(NULL));
    ssd->editbox->generic.column = 0;
    /* Reset columns so that the buttons are alongside the list, rather
     * than alongside that edit box. */
    ctrl_columns(s, 1, 100);
    ctrl_columns(s, 2, 75, 25);
    ssd->listbox = ctrl_listbox(s, NULL, NO_SHORTCUT,
				HELPCTX(session_saved),
				sessionsaver_handler, P(ssd));
    ssd->listbox->generic.column = 0;
    ssd->listbox->listbox.height = 7;
    if (!midsession) {
	ssd->loadbutton = ctrl_pushbutton(s, "加载", 'l',//"Load"
					  HELPCTX(session_saved),
					  sessionsaver_handler, P(ssd));
	ssd->loadbutton->generic.column = 1;
    } else {
	/* We can't offer the Load button mid-session, as it would allow the
	 * user to load and subsequently save settings they can't see. (And
	 * also change otherwise immutable settings underfoot; that probably
	 * shouldn't be a problem, but.) */
	ssd->loadbutton = NULL;
    }
    /* "Save" button is permitted mid-session. */
    ssd->savebutton = ctrl_pushbutton(s, "保存", 'v',//"Save"
				      HELPCTX(session_saved),
				      sessionsaver_handler, P(ssd));
    ssd->savebutton->generic.column = 1;
    if (!midsession) {
	ssd->delbutton = ctrl_pushbutton(s, "删除", 'd',//"Delete"
					 HELPCTX(session_saved),
					 sessionsaver_handler, P(ssd));
	ssd->delbutton->generic.column = 1;
    } else {
	/* Disable the Delete button mid-session too, for UI consistency. */
	ssd->delbutton = NULL;
    }
    ctrl_columns(s, 1, 100);

    s = ctrl_getset(b, "Session", "otheropts", NULL);
    ctrl_radiobuttons(s, "退出时关闭窗口:", 'x', 4,//"Close window on exit"
                      HELPCTX(session_coe),
                      conf_radiobutton_handler,
                      I(CONF_close_on_exit),
                      "总是", I(FORCE_ON),//"Always"
                      "从不", I(FORCE_OFF),//"Never"
                      "仅从容退出", I(AUTO), NULL);//"Only on clean exit"

    /*
     * The Session/Logging panel.
     */
    ctrl_settitle(b, "Session/Logging", "控制会话日志记录的选项");//

    s = ctrl_getset(b, "Session/Logging", "main", NULL);//
    /*
     * The logging buttons change depending on whether SSH packet
     * logging can sensibly be available.
     */
    {
	const char *sshlogname, *sshrawlogname;
	if ((midsession && protocol == PROT_SSH) ||
	    (!midsession && backend_from_proto(PROT_SSH))) {
	    sshlogname = "SSH数据包";//"SSH packets"
	    sshrawlogname = "SSH数据包和原始数据";//"SSH packets and raw data"
        } else {
	    sshlogname = NULL;	       /* this will disable both buttons */
	    sshrawlogname = NULL;      /* this will just placate optimisers */
        }
	ctrl_radiobuttons(s, "会话记录:", NO_SHORTCUT, 2,//"Session logging:"
			  HELPCTX(logging_main),
			  loggingbuttons_handler,
			  I(CONF_logtype),
			  "无", 't', I(LGTYP_NONE),//"None"
			  "可打印输出", 'p', I(LGTYP_ASCII),//"Printable output"
			  "所有会话输出", 'l', I(LGTYP_DEBUG),//"All session output"
			  sshlogname, 's', I(LGTYP_PACKETS),
			  sshrawlogname, 'r', I(LGTYP_SSHRAW),
			  NULL);
    }
    ctrl_filesel(s, "日志文件名:", 'f',//"Log file name:"
		 NULL, TRUE, "选择会话日志文件名",//"Select session log file name"
		 HELPCTX(logging_filename),
		 conf_filesel_handler, I(CONF_logfilename));
    ctrl_text(s, "(日志文件名可以包含 日期:[&Y, &M, &D],"
	      " 时间:[&T], 主机名:[&H] , 端口号:[&P])",//"(Log file name can contain &Y, &M, &D for date," " &T for time, &H for host name, and &P for port number)"
	      HELPCTX(logging_filename));
    ctrl_radiobuttons(s, "如果日志文件已经存在:", 'e', 1,//"What to do if the log file already exists:"
		      HELPCTX(logging_exists),
		      conf_radiobutton_handler, I(CONF_logxfovr),
		      "覆盖", I(LGXF_OVR),//"Always overwrite it"
		      "加到末尾", I(LGXF_APN),//"Always append to the end of it"
		      "总是询问", I(LGXF_ASK), NULL);//"Ask the user every time"
    ctrl_checkbox(s, "频繁刷新日志文件", 'u',//"Flush log file frequently"
		 HELPCTX(logging_flush),
		 conf_checkbox_handler, I(CONF_logflush));

    if ((midsession && protocol == PROT_SSH) ||
	(!midsession && backend_from_proto(PROT_SSH))) {
	s = ctrl_getset(b, "Session/Logging", "ssh",
			"SSH数据包日志细节选项");//"Options specific to SSH packet logging"
	ctrl_checkbox(s, "省略已知密码字段", 'k',//"Omit known password fields"
		      HELPCTX(logging_ssh_omit_password),
		      conf_checkbox_handler, I(CONF_logomitpass));
	ctrl_checkbox(s, "省略会话数据", 'd',//"Omit session data"
		      HELPCTX(logging_ssh_omit_data),
		      conf_checkbox_handler, I(CONF_logomitdata));
    }

    /*
     * The Terminal panel.
     */
    ctrl_settitle(b, "Terminal", "仿真终端控制选项");//"Options controlling the terminal emulation"

    s = ctrl_getset(b, "Terminal", "general", "设置各种终端选项");//"Set various terminal options"
    ctrl_checkbox(s, "自动换行模式打开", 'w',//"Auto wrap mode initially on"
		  HELPCTX(terminal_autowrap),
		  conf_checkbox_handler, I(CONF_wrap_mode));
    ctrl_checkbox(s, "DEC 源模式打开", 'd',//"DEC Origin Mode initially on"
		  HELPCTX(terminal_decom),
		  conf_checkbox_handler, I(CONF_dec_om));
    ctrl_checkbox(s, "每个换行中隐式回车", 'r',//"Implicit CR in every LF"
		  HELPCTX(terminal_lfhascr),
		  conf_checkbox_handler, I(CONF_lfhascr));
    ctrl_checkbox(s, "每个回车中隐式换行", 'f',//"Implicit LF in every CR"
		  HELPCTX(terminal_crhaslf),
		  conf_checkbox_handler, I(CONF_crhaslf));
    ctrl_checkbox(s, "使用背景颜色擦除屏幕", 'e',//"Use background colour to erase screen"
		  HELPCTX(terminal_bce),
		  conf_checkbox_handler, I(CONF_bce));
    ctrl_checkbox(s, "使文字闪烁", 'n',//"Enable blinking text"
		  HELPCTX(terminal_blink),
		  conf_checkbox_handler, I(CONF_blinktext));
    ctrl_editbox(s, "应答到 ^E:", 's', 100,//"Answerback to ^E:"
		 HELPCTX(terminal_answerback),
		 conf_editbox_handler, I(CONF_answerback), I(1));

    s = ctrl_getset(b, "Terminal", "ldisc", "行纪律选项");//"Line discipline options"
    ctrl_radiobuttons(s, "本地回应:", 'l', 3,//"Local echo:"
		      HELPCTX(terminal_localecho),
		      conf_radiobutton_handler,I(CONF_localecho),
		      "自动", I(AUTO),//"Auto"
		      "强制开", I(FORCE_ON),//"Force on"
		      "强制关", I(FORCE_OFF), NULL);//"Force off"
    ctrl_radiobuttons(s, "本地行编辑:", 't', 3,//"Local line editing:"
		      HELPCTX(terminal_localedit),
		      conf_radiobutton_handler,I(CONF_localedit),
		      "自动", I(AUTO),//"Auto"
		      "强制开", I(FORCE_ON),//"Force on"
		      "强制关", I(FORCE_OFF), NULL);//"Force off"

    s = ctrl_getset(b, "Terminal", "printing", "远端控制打印");//"Remote-controlled printing"
    ctrl_combobox(s, "打印机将ANSI打印输出到:", 'p', 100,//"Printer to send ANSI printer output to:"
		  HELPCTX(terminal_printing),
		  printerbox_handler, P(NULL), P(NULL));

    /*
     * The Terminal/Keyboard panel.
     */
    ctrl_settitle(b, "Terminal/Keyboard",
		  "控制键效果的选项");//"Options controlling the effects of keys"

    s = ctrl_getset(b, "Terminal/Keyboard", "mappings",
		    "更改发送的序列:");//"Change the sequences sent by:"
    ctrl_radiobuttons(s, "退格键", 'b', 2,//"The Backspace key"
		      HELPCTX(keyboard_backspace),
		      conf_radiobutton_handler,
		      I(CONF_bksp_is_delete),
		      "Control-H", I(0), "Control-? (127)", I(1), NULL);//""
    ctrl_radiobuttons(s, "`Home`和`End`键", 'e', 2,//"The Home and End keys"
		      HELPCTX(keyboard_homeend),
		      conf_radiobutton_handler,
		      I(CONF_rxvt_homeend),
		      "Standard", I(0), "rxvt", I(1), NULL);//""
    ctrl_radiobuttons(s, "功能键和键盘", 'f', 3,//"The Function keys and keypad"
		      HELPCTX(keyboard_funkeys),
		      conf_radiobutton_handler,
		      I(CONF_funky_type),
		      "ESC[n~", I(0), "Linux", I(1), "Xterm R6", I(2),
		      "VT400", I(3), "VT100+", I(4), "SCO", I(5), NULL);

    s = ctrl_getset(b, "Terminal/Keyboard", "appkeypad",
		    "软键盘设置:");//"Application keypad settings"
    ctrl_radiobuttons(s, "光标键的初始状态:", 'r', 3,//"Initial state of cursor keys:"
		      HELPCTX(keyboard_appcursor),
		      conf_radiobutton_handler,
		      I(CONF_app_cursor),
		      "Normal", I(0), "Application", I(1), NULL);
    ctrl_radiobuttons(s, "数字键盘的初始状态:", 'n', 3,//"Initial state of numeric keypad:"
		      HELPCTX(keyboard_appkeypad),
		      numeric_keypad_handler, P(NULL),
		      "Normal", I(0), "Application", I(1), "NetHack", I(2),
		      NULL);

    /*
     * The Terminal/Bell panel.
     */
    ctrl_settitle(b, "Terminal/Bell",
		  "终端响铃控制选项");//"Options controlling the terminal bell"

    s = ctrl_getset(b, "Terminal/Bell", "style", "设置响铃的风格");//"Set the style of bell"
    ctrl_radiobuttons(s, "当响铃时:", 'b', 1,//"Action to happen when a bell occurs:"
		      HELPCTX(bell_style),
		      conf_radiobutton_handler, I(CONF_beep),
		      "无(禁用响铃)", I(BELL_DISABLED),//"None (bell disabled)"
		      "使用默认系统警报声", I(BELL_DEFAULT),//"Make default system alert sound"
		      "可视响铃(闪烁窗口)", I(BELL_VISUAL), NULL);//"Visual bell (flash window)"

    s = ctrl_getset(b, "Terminal/Bell", "overload",
		    "控制铃声过载行为");//"Control the bell overload behaviour"
    ctrl_checkbox(s, "暂停响铃", 'd',//"Bell is temporarily disabled when over-used"
		  HELPCTX(bell_overload),
		  conf_checkbox_handler, I(CONF_bellovl));
    ctrl_editbox(s, "允许多个响铃", 'm', 20,//"Over-use means this many bells"
		 HELPCTX(bell_overload),
		 conf_editbox_handler, I(CONF_bellovl_n), I(-1));
    ctrl_editbox(s, "响铃秒数", 't', 20,//"... in this many seconds"
		 HELPCTX(bell_overload),
		 conf_editbox_handler, I(CONF_bellovl_t),
		 I(-TICKSPERSEC));
    ctrl_text(s, "几秒钟后,铃声重新启用",//"The bell is re-enabled after a few seconds of silence."
	      HELPCTX(bell_overload));
    ctrl_editbox(s, "沉默所需(秒)", 's', 20,//"Seconds of silence required"
		 HELPCTX(bell_overload),
		 conf_editbox_handler, I(CONF_bellovl_s),
		 I(-TICKSPERSEC));

    /*
     * The Terminal/Features panel.
     */
    ctrl_settitle(b, "Terminal/Features",
		  "启用和禁用高级终端功能");//"Enabling and disabling advanced terminal features"

    s = ctrl_getset(b, "Terminal/Features", "main", NULL);
    ctrl_checkbox(s, "禁用应用程序光标键模式", 'u',//"Disable application cursor keys mode"
		  HELPCTX(features_application),
		  conf_checkbox_handler, I(CONF_no_applic_c));
    ctrl_checkbox(s, "禁用软键盘模式", 'k',//"Disable application keypad mode"
		  HELPCTX(features_application),
		  conf_checkbox_handler, I(CONF_no_applic_k));
    ctrl_checkbox(s, "禁用鼠标xterm风格报告", 'x',//"Disable xterm-style mouse reporting"
		  HELPCTX(features_mouse),
		  conf_checkbox_handler, I(CONF_no_mouse_rep));
    ctrl_checkbox(s, "禁用远端调整大小", 's',//"Disable remote-controlled terminal resizing"
		  HELPCTX(features_resize),
		  conf_checkbox_handler,
		  I(CONF_no_remote_resize));
    ctrl_checkbox(s, "禁用切换到备用终端屏幕", 'w',//"Disable switching to alternate terminal screen"
		  HELPCTX(features_altscreen),
		  conf_checkbox_handler, I(CONF_no_alt_screen));
    ctrl_checkbox(s, "禁用远端更改窗口标题", 't',//"Disable remote-controlled window title changing"
		  HELPCTX(features_retitle),
		  conf_checkbox_handler,
		  I(CONF_no_remote_wintitle));
    ctrl_checkbox(s, "禁用远端清除滚动文档", 'e',//"Disable remote-controlled clearing of scrollback"
		  HELPCTX(features_clearscroll),
		  conf_checkbox_handler,
		  I(CONF_no_remote_clearscroll));
    ctrl_radiobuttons(s, "响应远端问询标题(安全):", 'q', 3,//"Response to remote title query (SECURITY):"
		      HELPCTX(features_qtitle),
		      conf_radiobutton_handler,
		      I(CONF_remote_qtitle_action),
		      "无", I(TITLE_NONE),//"None"
		      "空字符串", I(TITLE_EMPTY),//"Empty string"
		      "窗口标题", I(TITLE_REAL), NULL);//"Window title"
    ctrl_checkbox(s, "禁止服务器发送破坏性的退格键 ^?",'b',//"Disable destructive backspace on server sending ^?"
		  HELPCTX(features_dbackspace),
		  conf_checkbox_handler, I(CONF_no_dbackspace));
    ctrl_checkbox(s, "禁用远端控制字符集配置",//"Disable remote-controlled character set configuration"
		  'r', HELPCTX(features_charset), conf_checkbox_handler,
		  I(CONF_no_remote_charset));
    ctrl_checkbox(s, "禁用阿拉伯语文本样式",//"Disable Arabic text shaping"
		  'l', HELPCTX(features_arabicshaping), conf_checkbox_handler,
		  I(CONF_arabicshaping));
    ctrl_checkbox(s, "禁用双向文本显示",//"Disable bidirectional text display"
		  'd', HELPCTX(features_bidi), conf_checkbox_handler,
		  I(CONF_bidi));

    /*
     * The Window panel.
     */
    str = dupprintf("%s的窗口控制选项", appname);//"Options controlling %s's window"
    ctrl_settitle(b, "Window", str);
    sfree(str);

    s = ctrl_getset(b, "Window", "size", "设置窗口的大小");//"Set the size of the window"
    ctrl_columns(s, 2, 50, 50);
    c = ctrl_editbox(s, "列", 'm', 100,//"Columns"
		     HELPCTX(window_size),
		     conf_editbox_handler, I(CONF_width), I(-1));
    c->generic.column = 0;
    c = ctrl_editbox(s, "行", 'r', 100,//"Rows"
		     HELPCTX(window_size),
		     conf_editbox_handler, I(CONF_height),I(-1));
    c->generic.column = 1;
    ctrl_columns(s, 1, 100);

    s = ctrl_getset(b, "Window", "scrollback",
		    "窗口滚动文档控制");//"Control the scrollback in the window"
    ctrl_editbox(s, "可滚动行数", 's', 50,//"Lines of scrollback"
		 HELPCTX(window_scrollback),
		 conf_editbox_handler, I(CONF_savelines), I(-1));
    ctrl_checkbox(s, "显示滚动条", 'd',//"Display scrollbar"
		  HELPCTX(window_scrollback),
		  conf_checkbox_handler, I(CONF_scrollbar));
    ctrl_checkbox(s, "按键时重置滚动", 'k',//"Reset scrollback on keypress"
		  HELPCTX(window_scrollback),
		  conf_checkbox_handler, I(CONF_scroll_on_key));
    ctrl_checkbox(s, "显示活动时重置滚动", 'p',//"Reset scrollback on display activity"
		  HELPCTX(window_scrollback),
		  conf_checkbox_handler, I(CONF_scroll_on_disp));
    ctrl_checkbox(s, "删除滚动文档", 'e',//"Push erased text into scrollback"
		  HELPCTX(window_erased),
		  conf_checkbox_handler,
		  I(CONF_erase_to_scrollback));

    /*
     * The Window/Appearance panel.
     */
    str = dupprintf("配置%s窗口的外观", appname);//"Configure the appearance of %s's window"
    ctrl_settitle(b, "Window/Appearance", str);
    sfree(str);

    s = ctrl_getset(b, "Window/Appearance", "cursor",
		    "调整光标的使用");//Adjust the use of the cursor""
    ctrl_radiobuttons(s, "光标的外观:", NO_SHORTCUT, 3,//"Cursor appearance:"
		      HELPCTX(appearance_cursor),
		      conf_radiobutton_handler,
		      I(CONF_cursor_type),
		      "黑块", 'l', I(0),//"Block"
		      "下划线", 'u', I(1),//"Underline"
		      "竖线", 'v', I(2), NULL);//"Vertical line"
    ctrl_checkbox(s, "闪烁光标", 'b',//"Cursor blinks"
		  HELPCTX(appearance_cursor),
		  conf_checkbox_handler, I(CONF_blink_cur));

    s = ctrl_getset(b, "Window/Appearance", "font",
		    "字体设置");//"Font settings"
    ctrl_fontsel(s, "终端窗口中使用的字体", 'n',//"Font used in the terminal window"
		 HELPCTX(appearance_font),
		 conf_fontsel_handler, I(CONF_font));

    s = ctrl_getset(b, "Window/Appearance", "mouse",
		    "调整鼠标指针的使用");//"Adjust the use of the mouse pointer"
    ctrl_checkbox(s, "在窗口中键入时隐藏鼠标指针", 'p',//"Hide mouse pointer when typing in window"
		  HELPCTX(appearance_hidemouse),
		  conf_checkbox_handler, I(CONF_hide_mouseptr));

    s = ctrl_getset(b, "Window/Appearance", "border",
		    "调整窗口边框");//"Adjust the window border"
    ctrl_editbox(s, "文本和窗口边缘之间留间隙:", 'e', 20,//"Gap between text and window edge:"
		 HELPCTX(appearance_border),
		 conf_editbox_handler,
		 I(CONF_window_border), I(-1));

    /*
     * The Window/Behaviour panel.
     */
    str = dupprintf("配置%s窗口的行为", appname);//"Configure the behaviour of %s's window"
    ctrl_settitle(b, "Window/Behaviour", str);
    sfree(str);

    s = ctrl_getset(b, "Window/Behaviour", "title",
		    "调整窗口标题的行为");//"Adjust the behaviour of the window title"
    ctrl_editbox(s, "Window title:", 't', 100,//""
		 HELPCTX(appearance_title),
		 conf_editbox_handler, I(CONF_wintitle), I(1));
    ctrl_checkbox(s, "单独的窗口标题和图标", 'i',//"Separate window and icon titles"
		  HELPCTX(appearance_title),
		  conf_checkbox_handler,
		  I(CHECKBOX_INVERT | CONF_win_name_always));

    s = ctrl_getset(b, "Window/Behaviour", "main", NULL);
    ctrl_checkbox(s, "关闭窗口前警告", 'w',//"Warn before closing window"
		  HELPCTX(behaviour_closewarn),
		  conf_checkbox_handler, I(CONF_warn_on_close));

    /*
     * The Window/Translation panel.
     */
    ctrl_settitle(b, "Window/Translation",
		  "字符集转换控制选项");//"Options controlling character set translation"

    s = ctrl_getset(b, "Window/Translation", "trans",
		    "字符集转换");//"Character set translation"
    ctrl_combobox(s, "远端字符集:",//"Remote character set:"
		  'r', 100, HELPCTX(translation_codepage),
		  codepage_handler, P(NULL), P(NULL));

    s = ctrl_getset(b, "Window/Translation", "tweaks", NULL);
    ctrl_checkbox(s, "宽泛对待CJK模糊字符", 'w',//"Treat CJK ambiguous characters as wide"
		  HELPCTX(translation_cjk_ambig_wide),
		  conf_checkbox_handler, I(CONF_cjk_ambig_wide));

    str = dupprintf("调整%s如何处理线条绘制字符", appname);//"Adjust how %s handles line drawing characters"
    s = ctrl_getset(b, "Window/Translation", "linedraw", str);
    sfree(str);
    ctrl_radiobuttons(s, "线划字符的处理:", NO_SHORTCUT,1,//"Handling of line drawing characters:"
		      HELPCTX(translation_linedraw),
		      conf_radiobutton_handler,
		      I(CONF_vtmode),
		      "使用unicode点阵绘制",'u',I(VT_UNICODE),//"Use Unicode line drawing code points"
		      "细线绘制 (+, - and |)",'p',I(VT_POORMAN),//"Poor man's line drawing (+, - and |)"
		      NULL);
    ctrl_checkbox(s, "复制和粘贴绘制字符为lqqqk",'d',//"Copy and paste line drawing characters as lqqqk"
		  HELPCTX(selection_linedraw),
		  conf_checkbox_handler, I(CONF_rawcnp));

    /*
     * The Window/Selection panel.
     */
    ctrl_settitle(b, "Window/Selection", "控制复制和粘贴的选项");//"Options controlling copy and paste"
	
    s = ctrl_getset(b, "Window/Selection", "mouse",
		    "鼠标控制使用");//"Control use of mouse"
    ctrl_checkbox(s, "移位重写应用程序对鼠标的使用", 'p',//"Shift overrides application's use of mouse"
		  HELPCTX(selection_shiftdrag),
		  conf_checkbox_handler, I(CONF_mouse_override));
    ctrl_radiobuttons(s,
		      "默认选择模式 (Alt+拖拽 另一种):",//"Default selection mode (Alt+drag does the other one):"
		      NO_SHORTCUT, 2,
		      HELPCTX(selection_rect),
		      conf_radiobutton_handler,
		      I(CONF_rect_select),
		      "正常", 'n', I(0),//"Normal"
		      "矩形块", 'r', I(1), NULL);//"Rectangular block"

    s = ctrl_getset(b, "Window/Selection", "charclass",
		    "控制一次选择一个单词模式");//"Control the select-one-word-at-a-time mode"
    ccd = (struct charclass_data *)
	ctrl_alloc(b, sizeof(struct charclass_data));
    ccd->listbox = ctrl_listbox(s, "字符类:", 'e',//"Character classes:"
				HELPCTX(selection_charclasses),
				charclass_handler, P(ccd));
    ccd->listbox->listbox.multisel = 1;
    ccd->listbox->listbox.ncols = 4;
    ccd->listbox->listbox.percentages = snewn(4, int);
    ccd->listbox->listbox.percentages[0] = 15;
    ccd->listbox->listbox.percentages[1] = 25;
    ccd->listbox->listbox.percentages[2] = 20;
    ccd->listbox->listbox.percentages[3] = 40;
    ctrl_columns(s, 2, 67, 33);
    ccd->editbox = ctrl_editbox(s, "设置为类", 't', 50,//"Set to class"
				HELPCTX(selection_charclasses),
				charclass_handler, P(ccd), P(NULL));
    ccd->editbox->generic.column = 0;
    ccd->button = ctrl_pushbutton(s, "设置", 's',//"Set"
				  HELPCTX(selection_charclasses),
				  charclass_handler, P(ccd));
    ccd->button->generic.column = 1;
    ctrl_columns(s, 1, 100);

    /*
     * The Window/Colours panel.
     */
    ctrl_settitle(b, "Window/Colours", "控制使用的颜色选项");//"Options controlling use of colours"

    s = ctrl_getset(b, "Window/Colours", "general",
		    "颜色使用的一般选项");//"General options for colour usage"
    ctrl_checkbox(s, "允许终端指定ANSI颜色", 'i',//"Allow terminal to specify ANSI colours"
		  HELPCTX(colours_ansi),
		  conf_checkbox_handler, I(CONF_ansi_colour));
    ctrl_checkbox(s, "允许终端使用xterm 256颜色模式", '2',//"Allow terminal to use xterm 256-colour mode"
		  HELPCTX(colours_xterm256), conf_checkbox_handler,
		  I(CONF_xterm_256_colour));
    ctrl_radiobuttons(s, "显示粗体文本改变:", 'b', 3,//"Indicate bolded text by changing:"
                      HELPCTX(colours_bold),
                      conf_radiobutton_handler, I(CONF_bold_style),
                      "字体", I(1),//"The font"
                      "颜色", I(2),//"The colour"
                      "字体和颜色", I(3),//"Both"
                      NULL);

    str = dupprintf("调整%s显示的精确颜色", appname);//"Adjust the precise colours %s displays"
    s = ctrl_getset(b, "Window/Colours", "adjust", str);
    sfree(str);
    ctrl_text(s, "从列表中选择颜色,然后单击\"修改\"按钮以改其外观",//"Select a colour from the list, and then click the"" Modify button to change its appearance."
	      HELPCTX(colours_config));
    ctrl_columns(s, 2, 67, 33);
    cd = (struct colour_data *)ctrl_alloc(b, sizeof(struct colour_data));
    cd->listbox = ctrl_listbox(s, "选择颜色:", 'u',//"Select a colour to adjust:"
			       HELPCTX(colours_config), colour_handler, P(cd));
    cd->listbox->generic.column = 0;
    cd->listbox->listbox.height = 7;
    c = ctrl_text(s, "RGB:", HELPCTX(colours_config));//"RGB value"
    c->generic.column = 1;
    cd->redit = ctrl_editbox(s, "Red", 'r', 50, HELPCTX(colours_config),//""
			     colour_handler, P(cd), P(NULL));
    cd->redit->generic.column = 1;
    cd->gedit = ctrl_editbox(s, "Green", 'n', 50, HELPCTX(colours_config),//""
			     colour_handler, P(cd), P(NULL));
    cd->gedit->generic.column = 1;
    cd->bedit = ctrl_editbox(s, "Blue", 'e', 50, HELPCTX(colours_config),//""
			     colour_handler, P(cd), P(NULL));
    cd->bedit->generic.column = 1;
    cd->button = ctrl_pushbutton(s, "修改", 'm', HELPCTX(colours_config),//"Modify"
				 colour_handler, P(cd));
    cd->button->generic.column = 1;
    ctrl_columns(s, 1, 100);

    /*
     * The Connection panel. This doesn't show up if we're in a
     * non-network utility such as pterm. We tell this by being
     * passed a protocol < 0.
     */
    if (protocol >= 0) {
	ctrl_settitle(b, "Connection", "连接控制选项");//"Options controlling the connection"

	s = ctrl_getset(b, "Connection", "keepalive",
			"发送空包以保持会话活动");//"Sending of null packets to keep session active"
	ctrl_editbox(s, "保持会话活动秒数 (0:关闭)", 'k', 20,//"Seconds between keepalives (0 to turn off)"
		     HELPCTX(connection_keepalive),
		     conf_editbox_handler, I(CONF_ping_interval),
		     I(-1));

	if (!midsession) {
	    s = ctrl_getset(b, "Connection", "tcp",
			    "低级别TCP连接选项");//"Low-level TCP connection options"
	    ctrl_checkbox(s, "禁用Nagle的算法(TCP_NODELAY选项)",//"Disable Nagle's algorithm (TCP_NODELAY option)"
			  'n', HELPCTX(connection_nodelay),
			  conf_checkbox_handler,
			  I(CONF_tcp_nodelay));
	    ctrl_checkbox(s, "启用TCP保持活动 (SO_KEEPALIVE选项)",//"Enable TCP keepalives (SO_KEEPALIVE option)"
			  'p', HELPCTX(connection_tcpkeepalive),
			  conf_checkbox_handler,
			  I(CONF_tcp_keepalives));
#ifndef NO_IPV6
	    s = ctrl_getset(b, "Connection", "ipversion",
			  "互联网协议版本");//"Internet protocol version"
	    ctrl_radiobuttons(s, NULL, NO_SHORTCUT, 3,
			  HELPCTX(connection_ipversion),
			  conf_radiobutton_handler,
			  I(CONF_addressfamily),
			  "Auto", 'u', I(ADDRTYPE_UNSPEC),//""
			  "IPv4", '4', I(ADDRTYPE_IPV4),
			  "IPv6", '6', I(ADDRTYPE_IPV6),
			  NULL);
#endif

	    {
		const char *label = backend_from_proto(PROT_SSH) ?
		    "远端主机的逻辑名称(e.g. for SSH key lookup):" : //"Logical name of remote host (e.g. for SSH key lookup)"
		    "远端主机的逻辑名称:"; //"Logical name of remote host:"
		s = ctrl_getset(b, "Connection", "identity",
				"远端主机的逻辑名称");//"Logical name of remote host"
		ctrl_editbox(s, label, 'm', 100,
			     HELPCTX(connection_loghost),
			     conf_editbox_handler, I(CONF_loghost), I(1));
	    }
	}

	/*
	 * A sub-panel Connection/Data, containing options that
	 * decide on data to send to the server.
	 */
	if (!midsession) {
	    ctrl_settitle(b, "Connection/Data", "发送到服务器的数据");//"Data to send to the server"

	    s = ctrl_getset(b, "Connection/Data", "login",
			    "登录细节");//"Login details"
	    ctrl_editbox(s, "自动登录的用户名", 'u', 50,//"Auto-login username"
			 HELPCTX(connection_username),
			 conf_editbox_handler, I(CONF_username), I(1));
	    {
		/* We assume the local username is sufficiently stable
		 * to include on the dialog box. */
		char *user = get_username();
		char *userlabel = dupprintf("使用系统用户名 (%s)",//"Use system username (%s)"
					    user ? user : "");
		sfree(user);
		ctrl_radiobuttons(s, "未指定用户名时:", 'n', 4,//"When username is not specified:"
				  HELPCTX(connection_username_from_env),
				  conf_radiobutton_handler,
				  I(CONF_username_from_env),
				  "提示", I(FALSE),//"Prompt"
				  userlabel, I(TRUE),
				  NULL);
		sfree(userlabel);
	    }

	    s = ctrl_getset(b, "Connection/Data", "term",
			    "终端的细节");//"Terminal details"
	    ctrl_editbox(s, "终端类型的字符串", 't', 50,//"Terminal-type string"
			 HELPCTX(connection_termtype),
			 conf_editbox_handler, I(CONF_termtype), I(1));
	    ctrl_editbox(s, "终端速度", 's', 50,//"Terminal speeds"
			 HELPCTX(connection_termspeed),
			 conf_editbox_handler, I(CONF_termspeed), I(1));

	    s = ctrl_getset(b, "Connection/Data", "env",
			    "环境变量");//"Environment variables"
	    ctrl_columns(s, 2, 80, 20);
	    ed = (struct environ_data *)
		ctrl_alloc(b, sizeof(struct environ_data));
	    ed->varbox = ctrl_editbox(s, "变量名", 'v', 60,//"Variable"
				      HELPCTX(telnet_environ),
				      environ_handler, P(ed), P(NULL));
	    ed->varbox->generic.column = 0;
	    ed->valbox = ctrl_editbox(s, "值", 'l', 60,//"Value"
				      HELPCTX(telnet_environ),
				      environ_handler, P(ed), P(NULL));
	    ed->valbox->generic.column = 0;
	    ed->addbutton = ctrl_pushbutton(s, "添加", 'd',//"Add"
					    HELPCTX(telnet_environ),
					    environ_handler, P(ed));
	    ed->addbutton->generic.column = 1;
	    ed->rembutton = ctrl_pushbutton(s, "删除", 'r',//"Remove"
					    HELPCTX(telnet_environ),
					    environ_handler, P(ed));
	    ed->rembutton->generic.column = 1;
	    ctrl_columns(s, 1, 100);
	    ed->listbox = ctrl_listbox(s, NULL, NO_SHORTCUT,
				       HELPCTX(telnet_environ),
				       environ_handler, P(ed));
	    ed->listbox->listbox.height = 3;
	    ed->listbox->listbox.ncols = 2;
	    ed->listbox->listbox.percentages = snewn(2, int);
	    ed->listbox->listbox.percentages[0] = 30;
	    ed->listbox->listbox.percentages[1] = 70;
	}

    }

    if (!midsession) {
	/*
	 * The Connection/Proxy panel.
	 */
	ctrl_settitle(b, "Connection/Proxy",
		      "代理使用的控制选项");//"Options controlling proxy usage"

	s = ctrl_getset(b, "Connection/Proxy", "basics", NULL);
	ctrl_radiobuttons(s, "代理类型:", 't', 3,//"Proxy type:"
			  HELPCTX(proxy_type),
			  conf_radiobutton_handler,
			  I(CONF_proxy_type),
			  "None", I(PROXY_NONE),//""
			  "SOCKS 4", I(PROXY_SOCKS4),
			  "SOCKS 5", I(PROXY_SOCKS5),
			  "HTTP", I(PROXY_HTTP),
			  "Telnet", I(PROXY_TELNET),
			  NULL);
	ctrl_columns(s, 2, 80, 20);
	c = ctrl_editbox(s, "代理服务器的主机名", 'y', 100,//"Proxy hostname"
			 HELPCTX(proxy_main),
			 conf_editbox_handler,
			 I(CONF_proxy_host), I(1));
	c->generic.column = 0;
	c = ctrl_editbox(s, "端口", 'p', 100,//"Port"
			 HELPCTX(proxy_main),
			 conf_editbox_handler,
			 I(CONF_proxy_port),
			 I(-1));
	c->generic.column = 1;
	ctrl_columns(s, 1, 100);
	ctrl_editbox(s, "排除 主机名/IP", 'e', 100,//"Exclude Hosts/IPs"
		     HELPCTX(proxy_exclude),
		     conf_editbox_handler,
		     I(CONF_proxy_exclude_list), I(1));
	ctrl_checkbox(s, "考虑本地主机的连接代理", 'x',//"Consider proxying local host connections"
		      HELPCTX(proxy_exclude),
		      conf_checkbox_handler,
		      I(CONF_even_proxy_localhost));
	ctrl_radiobuttons(s, "在代理端执行DNS名称查找", 'd', 3,//"Do DNS name lookup at proxy end:"
			  HELPCTX(proxy_dns),
			  conf_radiobutton_handler,
			  I(CONF_proxy_dns),
			  "No", I(FORCE_OFF),
			  "Auto", I(AUTO),
			  "Yes", I(FORCE_ON), NULL);
	ctrl_editbox(s, "用户名", 'u', 60,//"Username"
		     HELPCTX(proxy_auth),
		     conf_editbox_handler,
		     I(CONF_proxy_username), I(1));
	c = ctrl_editbox(s, "密码", 'w', 60,//"Password"
			 HELPCTX(proxy_auth),
			 conf_editbox_handler,
			 I(CONF_proxy_password), I(1));
	c->editbox.password = 1;
	ctrl_editbox(s, "Telnet 命令", 'm', 100,//"Telnet command"
		     HELPCTX(proxy_command),
		     conf_editbox_handler,
		     I(CONF_proxy_telnet_command), I(1));

	ctrl_radiobuttons(s, "在终端窗口中打印代理诊断", 'r', 5,//"Print proxy diagnostics in the terminal window"
			  HELPCTX(proxy_logging),
			  conf_radiobutton_handler,
			  I(CONF_proxy_log_to_term),
			  "No", I(FORCE_OFF),
			  "Yes", I(FORCE_ON),
			  "只有在会话开始时", I(AUTO), NULL);//"Only until session starts"
    }

    /*
     * The Telnet panel exists in the base config box, and in a
     * mid-session reconfig box _if_ we're using Telnet.
     */
    if (!midsession || protocol == PROT_TELNET) {
	/*
	 * The Connection/Telnet panel.
	 */
	ctrl_settitle(b, "Connection/Telnet",
		      "Telnet连接控制选项");//"Options controlling Telnet connections"

	s = ctrl_getset(b, "Connection/Telnet", "protocol",
			"Telnet协议的调整");//"Telnet protocol adjustments"

	if (!midsession) {
	    ctrl_radiobuttons(s, "处理 OLD_ENVIRON 歧义:",//"Handling of OLD_ENVIRON ambiguity:"
			      NO_SHORTCUT, 2,
			      HELPCTX(telnet_oldenviron),
			      conf_radiobutton_handler,
			      I(CONF_rfc_environ),
			      "BSD (commonplace)", 'b', I(0),
			      "RFC 1408 (unusual)", 'f', I(1), NULL);
	    ctrl_radiobuttons(s, "Telnet协商模式", 't', 2,//"Telnet negotiation mode:"
			      HELPCTX(telnet_passive),
			      conf_radiobutton_handler,
			      I(CONF_passive_telnet),
			      "被动", I(1), "主动", I(0), NULL);//"Passive"  "Active"
	}
	ctrl_checkbox(s, "键盘发送Telnet特殊命令", 'k',//"Keyboard sends Telnet special commands"
		      HELPCTX(telnet_specialkeys),
		      conf_checkbox_handler,
		      I(CONF_telnet_keyboard));
	ctrl_checkbox(s, "Telnet 行用回车键代替 ^M",//"Return key sends Telnet New Line instead of ^M"
		      'm', HELPCTX(telnet_newline),
		      conf_checkbox_handler,
		      I(CONF_telnet_newline));
    }

    if (!midsession) {

	/*
	 * The Connection/Rlogin panel.
	 */
	ctrl_settitle(b, "Connection/Rlogin",
		      "远程登录连接控制选项");//"Options controlling Rlogin connections"

	s = ctrl_getset(b, "Connection/Rlogin", "data",
			"发送到服务器的数据");//"Data to send to the server"
	ctrl_editbox(s, "本地用户名", 'l', 50,//"Local username:""
		     HELPCTX(rlogin_localuser),
		     conf_editbox_handler, I(CONF_localusername), I(1));
    }

    /*
     * All the SSH stuff is omitted in PuTTYtel, or in a reconfig
     * when we're not doing SSH.
     */

    if (backend_from_proto(PROT_SSH) && (!midsession || protocol == PROT_SSH)) {

	/*
	 * The Connection/SSH panel.
	 */
	ctrl_settitle(b, "Connection/SSH",
		      "SSH连接控制选项");//"Options controlling SSH connections"

	/* SSH-1 or connection-sharing downstream */
	if (midsession && (protcfginfo == 1 || protcfginfo == -1)) {
	    s = ctrl_getset(b, "Connection/SSH", "disclaimer", NULL);
	    ctrl_text(s, "此面板内容不能在会话中重新配置; 它只能在现在配置，所以它的子面板可以存在也不会看起来奇怪.", HELPCTX(no_help));
		//"Nothing on this panel may be reconfigured in mid-session; it is only here so that sub-panels of it can exist without looking strange."
	}

	if (!midsession) {

	    s = ctrl_getset(b, "Connection/SSH", "data",
			    "发送到服务器的数据");//"Data to send to the server"
	    ctrl_editbox(s, "远端命令:", 'r', 100,//"Remote command:"
			 HELPCTX(ssh_command),
			 conf_editbox_handler, I(CONF_remote_cmd), I(1));

	    s = ctrl_getset(b, "Connection/SSH", "protocol", "协议选项");//"Protocol options"
	    ctrl_checkbox(s, "从不启动shell或命令", 'n',//"Don't start a shell or command at all"
			  HELPCTX(ssh_noshell),
			  conf_checkbox_handler,
			  I(CONF_ssh_no_shell));
	}

	if (!midsession || !(protcfginfo == 1 || protcfginfo == -1)) {
	    s = ctrl_getset(b, "Connection/SSH", "protocol", "协议选项");//"Protocol options"

	    ctrl_checkbox(s, "启用压缩", 'e',//"Enable compression"
			  HELPCTX(ssh_compress),
			  conf_checkbox_handler,
			  I(CONF_compression));
	}

	if (!midsession) {
	    s = ctrl_getset(b, "Connection/SSH", "sharing", "在PuTTY工具之间共享SSH连接");//"Sharing an SSH connection between PuTTY tools"

	    ctrl_checkbox(s, "若可能,共享SSH连接", 's',//"Share SSH connections if possible"
			  HELPCTX(ssh_share),
			  conf_checkbox_handler,
			  I(CONF_ssh_connection_sharing));

            ctrl_text(s, "在共享连接中允许角色:",//"Permitted roles in a shared connection:"
                      HELPCTX(ssh_share));
	    ctrl_checkbox(s, "上游(连接到真实的服务器)", 'u',//"Upstream (connecting to the real server)"
			  HELPCTX(ssh_share),
			  conf_checkbox_handler,
			  I(CONF_ssh_connection_sharing_upstream));
	    ctrl_checkbox(s, "下游(连接上游PuTTY)", 'd',//"Downstream (connecting to the upstream PuTTY)"
			  HELPCTX(ssh_share),
			  conf_checkbox_handler,
			  I(CONF_ssh_connection_sharing_downstream));
	}

	if (!midsession) {
	    s = ctrl_getset(b, "Connection/SSH", "protocol", "Protocol options");//"协议选项"

	    ctrl_radiobuttons(s, "SSH协议版本:", NO_SHORTCUT, 2,//"SSH protocol version:"
			      HELPCTX(ssh_protocol),
			      conf_radiobutton_handler,
			      I(CONF_sshprot),
			      "2", '2', I(3),
			      "1 (不安全)", '1', I(0), NULL);//"INSECURE"
	}

	/*
	 * The Connection/SSH/Kex panel. (Owing to repeat key
	 * exchange, much of this is meaningful in mid-session _if_
	 * we're using SSH-2 and are not a connection-sharing
	 * downstream, or haven't decided yet.)
	 */
	if (protcfginfo != 1 && protcfginfo != -1) {
	    ctrl_settitle(b, "Connection/SSH/Kex",
			  "控制SSH密钥交换的选项");//"Options controlling SSH key exchange"

	    s = ctrl_getset(b, "Connection/SSH/Kex", "main",
			    "密钥交换算法选项");//"Key exchange algorithm options"
	    c = ctrl_draglist(s, "算法选择策略:", 's',//"Algorithm selection policy:"
			      HELPCTX(ssh_kexlist),
			      kexlist_handler, P(NULL));
	    c->listbox.height = 5;

	    s = ctrl_getset(b, "Connection/SSH/Kex", "repeat",
			    "控制密钥重新交换的选项");//"Options controlling key re-exchange"

	    ctrl_editbox(s, "重新键入之前的最大分钟数(0为无限制)", 't', 20,//"Max minutes before rekey (0 for no limit)"
			 HELPCTX(ssh_kex_repeat),
			 conf_editbox_handler,
			 I(CONF_ssh_rekey_time),
			 I(-1));
	    ctrl_editbox(s, "重新键入之前的最大数据(0为无限制)", 'x', 20,//"Max data before rekey (0 for no limit)"
			 HELPCTX(ssh_kex_repeat),
			 conf_editbox_handler,
			 I(CONF_ssh_rekey_data),
			 I(16));
	    ctrl_text(s, "(使用1M为1兆字节，1G为1千兆字节等)",//"(Use 1M for 1 megabyte, 1G for 1 gigabyte etc)"
		      HELPCTX(ssh_kex_repeat));
	}

	/*
	 * The 'Connection/SSH/Host keys' panel.
	 */
	if (protcfginfo != 1 && protcfginfo != -1) {
	    ctrl_settitle(b, "Connection/SSH/Host keys",
			  "控制SSH主机密钥的选项");//"Options controlling SSH host keys"

	    s = ctrl_getset(b, "Connection/SSH/Host keys", "main",
			    "主机密钥算法偏好");//"Host key algorithm preference"
	    c = ctrl_draglist(s, "算法选择策略:", 's',//"Algorithm selection policy:"
			      HELPCTX(ssh_hklist),
			      hklist_handler, P(NULL));
	    c->listbox.height = 5;
	}

	/*
	 * Manual host key configuration is irrelevant mid-session,
	 * as we enforce that the host key for rekeys is the
	 * same as that used at the start of the session.
	 */
	if (!midsession) {
	    s = ctrl_getset(b, "Connection/SSH/Host keys", "hostkeys",
			    "手动配置此连接的主机密钥");//"Manually configure host keys for this connection"

            ctrl_columns(s, 2, 75, 25);
            c = ctrl_text(s, "主机键或指纹接受:",//"Host keys or fingerprints to accept:"
                          HELPCTX(ssh_kex_manual_hostkeys));
            c->generic.column = 0;
            /* You want to select from the list, _then_ hit Remove. So
             * tab order should be that way round. */
            mh = (struct manual_hostkey_data *)
                ctrl_alloc(b,sizeof(struct manual_hostkey_data));
            mh->rembutton = ctrl_pushbutton(s, "删除", 'r',//"Remove"
                                            HELPCTX(ssh_kex_manual_hostkeys),
                                            manual_hostkey_handler, P(mh));
            mh->rembutton->generic.column = 1;
            mh->rembutton->generic.tabdelay = 1;
            mh->listbox = ctrl_listbox(s, NULL, NO_SHORTCUT,
                                       HELPCTX(ssh_kex_manual_hostkeys),
                                       manual_hostkey_handler, P(mh));
            /* This list box can't be very tall, because there's not
             * much room in the pane on Windows at least. This makes
             * it become really unhelpful if a horizontal scrollbar
             * appears, so we suppress that. */
            mh->listbox->listbox.height = 2;
            mh->listbox->listbox.hscroll = FALSE;
            ctrl_tabdelay(s, mh->rembutton);
	    mh->keybox = ctrl_editbox(s, "密钥", 'k', 80,//"Key"
                                      HELPCTX(ssh_kex_manual_hostkeys),
                                      manual_hostkey_handler, P(mh), P(NULL));
            mh->keybox->generic.column = 0;
            mh->addbutton = ctrl_pushbutton(s, "添加密钥", 'y',//"Add key"
                                            HELPCTX(ssh_kex_manual_hostkeys),
                                            manual_hostkey_handler, P(mh));
            mh->addbutton->generic.column = 1;
            ctrl_columns(s, 1, 100);
	}

	if (!midsession || !(protcfginfo == 1 || protcfginfo == -1)) {
	    /*
	     * The Connection/SSH/Cipher panel.
	     */
	    ctrl_settitle(b, "Connection/SSH/Cipher",
			  "控制SSH加密的选项");//"Options controlling SSH encryption"

	    s = ctrl_getset(b, "Connection/SSH/Cipher",
                            "encryption", "加密选项");//"Encryption options"
	    c = ctrl_draglist(s, "加密密码选择策略:", 's',//"Encryption cipher selection policy:"
			      HELPCTX(ssh_ciphers),
			      cipherlist_handler, P(NULL));
	    c->listbox.height = 6;

	    ctrl_checkbox(s, "在SSH-2中启用单DES的传统使用", 'i',//"Enable legacy use of single-DES in SSH-2"
			  HELPCTX(ssh_ciphers),
			  conf_checkbox_handler,
			  I(CONF_ssh2_des_cbc));
	}

	if (!midsession) {

	    /*
	     * The Connection/SSH/Auth panel.
	     */
	    ctrl_settitle(b, "Connection/SSH/Auth",
			  "SSH认证控制选项");//"Options controlling SSH authentication"

	    s = ctrl_getset(b, "Connection/SSH/Auth", "main", NULL);
	    ctrl_checkbox(s, "显示预认证横幅(仅SSH-2)",//"Display pre-authentication banner (SSH-2 only)"
			  'd', HELPCTX(ssh_auth_banner),
			  conf_checkbox_handler,
			  I(CONF_ssh_show_banner));
	    ctrl_checkbox(s, "完全绕过认证(仅SSH-2)", 'b',//"Bypass authentication entirely (SSH-2 only)"
			  HELPCTX(ssh_auth_bypass),
			  conf_checkbox_handler,
			  I(CONF_ssh_no_userauth));

	    s = ctrl_getset(b, "Connection/SSH/Auth", "methods",
			    "认证模式");//"Authentication methods"
	    ctrl_checkbox(s, "尝试使用Pageant认证", 'p',//"Attempt authentication using Pageant"
			  HELPCTX(ssh_auth_pageant),
			  conf_checkbox_handler,
			  I(CONF_tryagent));
	    ctrl_checkbox(s, "尝试TIS或密码卡认证(SSH-1)", 'm',//"Attempt TIS or CryptoCard auth (SSH-1)"
			  HELPCTX(ssh_auth_tis),
			  conf_checkbox_handler,
			  I(CONF_try_tis_auth));
	    ctrl_checkbox(s, "尝试键盘交互式认证(SSH-2)",//"Attempt \"keyboard-interactive\" auth (SSH-2)"
			  'i', HELPCTX(ssh_auth_ki),
			  conf_checkbox_handler,
			  I(CONF_try_ki_auth));

	    s = ctrl_getset(b, "Connection/SSH/Auth", "params",
			    "认证参数");//"Authentication parameters"
	    ctrl_checkbox(s, "允许代理转发", 'f',//"Allow agent forwarding"
			  HELPCTX(ssh_auth_agentfwd),
			  conf_checkbox_handler, I(CONF_agentfwd));
	    ctrl_checkbox(s, "SSH-2上运行尝试更改用户名", NO_SHORTCUT,//"Allow attempted changes of username in SSH-2"
			  HELPCTX(ssh_auth_changeuser),
			  conf_checkbox_handler,
			  I(CONF_change_username));
	    ctrl_filesel(s, "用于身份验证的私钥文件:", 'k',//"Private key file for authentication"
			 FILTER_KEY_FILES, FALSE, "选择私钥文件",//"Select private key file"
			 HELPCTX(ssh_auth_privkey),
			 conf_filesel_handler, I(CONF_keyfile));

#ifndef NO_GSSAPI
	    /*
	     * Connection/SSH/Auth/GSSAPI, which sadly won't fit on
	     * the main Auth panel.
	     */
	    ctrl_settitle(b, "Connection/SSH/Auth/GSSAPI",
			  "GSSAPI认证控制选项");//"Options controlling GSSAPI authentication"
	    s = ctrl_getset(b, "Connection/SSH/Auth/GSSAPI", "gssapi", NULL);

	    ctrl_checkbox(s, "尝试GSSAPI认证(仅SSH-2)",//"Attempt GSSAPI authentication (SSH-2 only)"
			  't', HELPCTX(ssh_gssapi),
			  conf_checkbox_handler,
			  I(CONF_try_gssapi_auth));

	    ctrl_checkbox(s, "允许GSSAPI证书委托", 'l',//"Allow GSSAPI credential delegation"
			  HELPCTX(ssh_gssapi_delegation),
			  conf_checkbox_handler,
			  I(CONF_gssapifwd));

	    /*
	     * GSSAPI library selection.
	     */
	    if (ngsslibs > 1) {
		c = ctrl_draglist(s, "GSSAPI库优先顺序:",//"Preference order for GSSAPI libraries"
				  'p', HELPCTX(ssh_gssapi_libraries),
				  gsslist_handler, P(NULL));
		c->listbox.height = ngsslibs;

		/*
		 * I currently assume that if more than one GSS
		 * library option is available, then one of them is
		 * 'user-supplied' and so we should present the
		 * following file selector. This is at least half-
		 * reasonable, because if we're using statically
		 * linked GSSAPI then there will only be one option
		 * and no way to load from a user-supplied library,
		 * whereas if we're using dynamic libraries then
		 * there will almost certainly be some default
		 * option in addition to a user-supplied path. If
		 * anyone ever ports PuTTY to a system on which
		 * dynamic-library GSSAPI is available but there is
		 * absolutely no consensus on where to keep the
		 * libraries, there'll need to be a flag alongside
		 * ngsslibs to control whether the file selector is
		 * displayed. 
		 */

		ctrl_filesel(s, "用户提供的GSSAPI库路径:", 's',//"User-supplied GSSAPI library path:"
			     FILTER_DYNLIB_FILES, FALSE, "选择库文件",//"Select library file"
			     HELPCTX(ssh_gssapi_libraries),
			     conf_filesel_handler,
			     I(CONF_ssh_gss_custom));
	    }
#endif
	}

	if (!midsession) {
	    /*
	     * The Connection/SSH/TTY panel.
	     */
	    ctrl_settitle(b, "Connection/SSH/TTY", "远端终端的设置");//"Remote terminal settings"

	    s = ctrl_getset(b, "Connection/SSH/TTY", "sshtty", NULL);
	    ctrl_checkbox(s, "不要分配伪终端", 'p',//"Don't allocate a pseudo-terminal"
			  HELPCTX(ssh_nopty),
			  conf_checkbox_handler,
			  I(CONF_nopty));

	    s = ctrl_getset(b, "Connection/SSH/TTY", "ttymodes",
			    "终端模式");//"Terminal modes"
	    td = (struct ttymodes_data *)
		ctrl_alloc(b, sizeof(struct ttymodes_data));
	    c = ctrl_text(s, "发送终端模式:", HELPCTX(ssh_ttymodes));//"Terminal modes to send:"
	    td->listbox = ctrl_listbox(s, NULL, NO_SHORTCUT,
				       HELPCTX(ssh_ttymodes),
				       ttymodes_handler, P(td));
	    td->listbox->listbox.height = 8;
	    td->listbox->listbox.ncols = 2;
	    td->listbox->listbox.percentages = snewn(2, int);
	    td->listbox->listbox.percentages[0] = 40;
	    td->listbox->listbox.percentages[1] = 60;
	    ctrl_columns(s, 2, 75, 25);
	    c = ctrl_text(s, "对于选定的模式,发送:", HELPCTX(ssh_ttymodes));//"For selected mode, send:"
	    c->generic.column = 0;
	    td->setbutton = ctrl_pushbutton(s, "设置", 's',//"Set"
					    HELPCTX(ssh_ttymodes),
					    ttymodes_handler, P(td));
	    td->setbutton->generic.column = 1;
	    td->setbutton->generic.tabdelay = 1;
	    ctrl_columns(s, 1, 100);	    /* column break */
	    /* Bit of a hack to get the value radio buttons and
	     * edit-box on the same row. */
	    ctrl_columns(s, 2, 75, 25);
	    td->valradio = ctrl_radiobuttons(s, NULL, NO_SHORTCUT, 3,
					     HELPCTX(ssh_ttymodes),
					     ttymodes_handler, P(td),
					     "自动", NO_SHORTCUT, P(NULL),//"Auto"
					     "无", NO_SHORTCUT, P(NULL),//"Nothing"
					     "当前:", NO_SHORTCUT, P(NULL),//"This:"
					     NULL);
	    td->valradio->generic.column = 0;
	    td->valbox = ctrl_editbox(s, NULL, NO_SHORTCUT, 100,
				      HELPCTX(ssh_ttymodes),
				      ttymodes_handler, P(td), P(NULL));
	    td->valbox->generic.column = 1;
	    ctrl_tabdelay(s, td->setbutton);
	}

	if (!midsession) {
	    /*
	     * The Connection/SSH/X11 panel.
	     */
	    ctrl_settitle(b, "Connection/SSH/X11",
			  "SSH X11转发控制选项");//"Options controlling SSH X11 forwarding"

	    s = ctrl_getset(b, "Connection/SSH/X11", "x11", "X11转发");//"X11 forwarding"
	    ctrl_checkbox(s, "使用X11转发", 'e',//"Enable X11 forwarding"
			  HELPCTX(ssh_tunnels_x11),
			  conf_checkbox_handler,I(CONF_x11_forward));
	    ctrl_editbox(s, "X显示位置", 'x', 50,//"X display location"
			 HELPCTX(ssh_tunnels_x11),
			 conf_editbox_handler, I(CONF_x11_display), I(1));
	    ctrl_radiobuttons(s, "远端X11认证协议", 'u', 2,//"Remote X11 authentication protocol"
			      HELPCTX(ssh_tunnels_x11auth),
			      conf_radiobutton_handler,
			      I(CONF_x11_auth),
			      "MIT-Magic-Cookie-1", I(X11_MIT),
			      "XDM-Authorization-1", I(X11_XDM), NULL);
	}

	/*
	 * The Tunnels panel _is_ still available in mid-session.
	 */
	ctrl_settitle(b, "Connection/SSH/Tunnels",
		      "SSH端口转发控制选项");//"Options controlling SSH port forwarding"

	s = ctrl_getset(b, "Connection/SSH/Tunnels", "portfwd",
			"端口转发");//"Port forwarding"
	ctrl_checkbox(s, "本地端口接受来自其他主机的连接",'t',//"Local ports accept connections from other hosts"
		      HELPCTX(ssh_tunnels_portfwd_localhost),
		      conf_checkbox_handler,
		      I(CONF_lport_acceptall));
	ctrl_checkbox(s, "远程端口执行相同的操作(仅SSH-2)", 'p',//"Remote ports do the same (SSH-2 only)"
		      HELPCTX(ssh_tunnels_portfwd_localhost),
		      conf_checkbox_handler,
		      I(CONF_rport_acceptall));

	ctrl_columns(s, 3, 55, 20, 25);
	c = ctrl_text(s, "Forwarded ports:", HELPCTX(ssh_tunnels_portfwd));//""
	c->generic.column = COLUMN_FIELD(0,2);
	/* You want to select from the list, _then_ hit Remove. So tab order
	 * should be that way round. */
	pfd = (struct portfwd_data *)ctrl_alloc(b,sizeof(struct portfwd_data));
	pfd->rembutton = ctrl_pushbutton(s, "远端", 'r',//"Remove"
					 HELPCTX(ssh_tunnels_portfwd),
					 portfwd_handler, P(pfd));
	pfd->rembutton->generic.column = 2;
	pfd->rembutton->generic.tabdelay = 1;
	pfd->listbox = ctrl_listbox(s, NULL, NO_SHORTCUT,
				    HELPCTX(ssh_tunnels_portfwd),
				    portfwd_handler, P(pfd));
	pfd->listbox->listbox.height = 3;
	pfd->listbox->listbox.ncols = 2;
	pfd->listbox->listbox.percentages = snewn(2, int);
	pfd->listbox->listbox.percentages[0] = 20;
	pfd->listbox->listbox.percentages[1] = 80;
	ctrl_tabdelay(s, pfd->rembutton);
	ctrl_text(s, "添加新的转发端口:", HELPCTX(ssh_tunnels_portfwd));//"Add new forwarded port:"
	/* You want to enter source, destination and type, _then_ hit Add.
	 * Again, we adjust the tab order to reflect this. */
	pfd->addbutton = ctrl_pushbutton(s, "添加", 'd',//"Add"
					 HELPCTX(ssh_tunnels_portfwd),
					 portfwd_handler, P(pfd));
	pfd->addbutton->generic.column = 2;
	pfd->addbutton->generic.tabdelay = 1;
	pfd->sourcebox = ctrl_editbox(s, "源端口", 's', 40,//"Source port"
				      HELPCTX(ssh_tunnels_portfwd),
				      portfwd_handler, P(pfd), P(NULL));
	pfd->sourcebox->generic.column = 0;
	pfd->destbox = ctrl_editbox(s, "目标", 'i', 67,//"Destination"
				    HELPCTX(ssh_tunnels_portfwd),
				    portfwd_handler, P(pfd), P(NULL));
	pfd->direction = ctrl_radiobuttons(s, NULL, NO_SHORTCUT, 3,
					   HELPCTX(ssh_tunnels_portfwd),
					   portfwd_handler, P(pfd),
					   "本地", 'l', P(NULL),//"Local"
					   "远端", 'm', P(NULL),//"Remote"
					   "动态", 'y', P(NULL),//"Dynamic"
					   NULL);
#ifndef NO_IPV6
	pfd->addressfamily =
	    ctrl_radiobuttons(s, NULL, NO_SHORTCUT, 3,
			      HELPCTX(ssh_tunnels_portfwd_ipversion),
			      portfwd_handler, P(pfd),
			      "Auto", 'u', I(ADDRTYPE_UNSPEC),//""
			      "IPv4", '4', I(ADDRTYPE_IPV4),
			      "IPv6", '6', I(ADDRTYPE_IPV6),
			      NULL);
#endif
	ctrl_tabdelay(s, pfd->addbutton);
	ctrl_columns(s, 1, 100);

	if (!midsession) {
	    /*
	     * The Connection/SSH/Bugs panels.
	     */
	    ctrl_settitle(b, "Connection/SSH/Bugs",
			  "SSH服务器错误的解决方法");//"Workarounds for SSH server bugs"

	    s = ctrl_getset(b, "Connection/SSH/Bugs", "main",
			    "检测SSH服务器中的已知错误");//"Detection of known bugs in SSH servers"
	    ctrl_droplist(s, "SSH-2忽略消息时的阻塞", '2', 20,//"Chokes on SSH-2 ignore messages"
			  HELPCTX(ssh_bugs_ignore2),
			  sshbug_handler, I(CONF_sshbug_ignore2));
	    ctrl_droplist(s, "处理SSH-2密钥重新交换失败", 'k', 20,//"Handles SSH-2 key re-exchange badly"
			  HELPCTX(ssh_bugs_rekey2),
			  sshbug_handler, I(CONF_sshbug_rekey2));
	    ctrl_droplist(s, "PuTTY在SSH-2请求'winadj'时阻塞", 'j',//"Chokes on PuTTY's SSH-2 'winadj' requests"
                          20, HELPCTX(ssh_bugs_winadj),
			  sshbug_handler, I(CONF_sshbug_winadj));
	    ctrl_droplist(s, "回复关闭通道时的请求", 'q', 20,//"Replies to requests on closed channels"
			  HELPCTX(ssh_bugs_chanreq),
			  sshbug_handler, I(CONF_sshbug_chanreq));
	    ctrl_droplist(s, "忽略SSH-2最大数据包大小", 'x', 20,//"Ignores SSH-2 maximum packet size"
			  HELPCTX(ssh_bugs_maxpkt2),
			  sshbug_handler, I(CONF_sshbug_maxpkt2));

	    ctrl_settitle(b, "Connection/SSH/More bugs",
			  "为进一步解决SSH服务器错误");//"Further workarounds for SSH server bugs"

	    s = ctrl_getset(b, "Connection/SSH/More bugs", "main",
			    "在SSH服务器中检测已知错误");//"Detection of known bugs in SSH servers"
	    ctrl_droplist(s, "需要对SSH-2 RSA签名填充", 'p', 20,//"Requires padding on SSH-2 RSA signatures"
			  HELPCTX(ssh_bugs_rsapad2),
			  sshbug_handler, I(CONF_sshbug_rsapad2));
	    ctrl_droplist(s, "仅支持pre-RFC4419 SSH-2 DH GEX", 'd', 20,//"Only supports pre-RFC4419 SSH-2 DH GEX"
			  HELPCTX(ssh_bugs_oldgex2),
			  sshbug_handler, I(CONF_sshbug_oldgex2));
	    ctrl_droplist(s, "SSH-2 HMAC密钥计算错误", 'm', 20,//"Miscomputes SSH-2 HMAC keys"
			  HELPCTX(ssh_bugs_hmac2),
			  sshbug_handler, I(CONF_sshbug_hmac2));
	    ctrl_droplist(s, "在SSH-2 PK认证中滥用会话ID", 'n', 20,//"Misuses the session ID in SSH-2 PK auth"
			  HELPCTX(ssh_bugs_pksessid2),
			  sshbug_handler, I(CONF_sshbug_pksessid2));
	    ctrl_droplist(s, "SSH-2加密密钥计算错误", 'e', 20,//"Miscomputes SSH-2 encryption keys"
			  HELPCTX(ssh_bugs_derivekey2),
			  sshbug_handler, I(CONF_sshbug_derivekey2));
	    ctrl_droplist(s, "SSH-1忽略消息时的阻塞", 'i', 20,//"Chokes on SSH-1 ignore messages"
			  HELPCTX(ssh_bugs_ignore1),
			  sshbug_handler, I(CONF_sshbug_ignore1));
	    ctrl_droplist(s, "拒绝所有SSH-1密码伪装", 's', 20,//"Refuses all SSH-1 password camouflage"
			  HELPCTX(ssh_bugs_plainpw1),
			  sshbug_handler, I(CONF_sshbug_plainpw1));
	    ctrl_droplist(s, "SSH-1 RSA认证时的阻塞", 'r', 20,//"Chokes on SSH-1 RSA authentication"
			  HELPCTX(ssh_bugs_rsa1),
			  sshbug_handler, I(CONF_sshbug_rsa1));
	}
    }
}
