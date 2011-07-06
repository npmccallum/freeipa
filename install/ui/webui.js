/*jsl:import ipa.js */
/*jsl:import navigation.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* REQUIRES: everything, this file puts it all togheter */

/* tabs definition for IPA webUI */

IPA.admin_navigation = function(spec) {

    spec = spec || {};

    spec.name = 'admin';

    spec.tabs = [
        {name: 'identity', label: IPA.messages.tabs.identity, children: [
            {entity: 'user'},
            {entity: 'group'},
            {entity: 'host'},
            {entity: 'hostgroup'},
            {entity: 'netgroup'},
            {entity: 'service'}
        ]},
        {name: 'policy', label: IPA.messages.tabs.policy, children: [
            {entity: 'dnszone', label: IPA.messages.tabs.dns},
            {name: 'hbac', label: IPA.messages.tabs.hbac, children: [
                 {entity: 'hbacrule'},
                 {entity: 'hbacsvc'},
                 {entity: 'hbacsvcgroup'}
            ]},
            {name: 'sudo', label: IPA.messages.tabs.sudo, children: [
                 {entity: 'sudorule'},
                 {entity: 'sudocmd'},
                 {entity: 'sudocmdgroup'}
            ]},
            {name:'automount',
             label: IPA.messages.tabs.automount,
             children:[
                {entity: 'automountlocation', hidden:true},
                {entity: 'automountmap', hidden: true},
                {entity: 'automountkey', hidden: true}]},
            {entity: 'pwpolicy'},
            {entity: 'krbtpolicy'}
        ]},
        {name: 'ipaserver', label: IPA.messages.tabs.ipaserver, children: [
            {name: 'rolebased', label: IPA.messages.tabs.role, children: [
                 {entity: 'role'},
                 {entity: 'privilege'},
                 {entity: 'permission'}
             ]},
            {entity: 'selfservice'},
            {entity: 'delegation'},
            {entity: 'entitle'},
            {entity: 'config'}
        ]}];

    var that = IPA.navigation(spec);

    return that;
};

IPA.self_serv_navigation = function(spec) {

    spec = spec || {};

    spec.name = 'self-service';

    spec.tabs = [
        {name: 'identity', label: IPA.messages.tabs.identity, children: [
            {entity: 'user'}
        ]}];

    var that = IPA.navigation(spec);

    that.update = function() {
        var pkey = that.get_state('user-pkey');
        var facet = that.get_state('user-facet');

        if (pkey && facet) {
            that.navigation_update();

        } else {
            var state = {
                'navigation': 'identity',
                'identity': 'user',
                'user-pkey': pkey || IPA.whoami_pkey,
                'user-facet': facet || 'details'
            };
            that.push_state(state);
        }
    };

    return that;
};

/* main (document onready event handler) */
$(function() {



    /* main loop (hashchange event handler) */
    function window_hashchange(evt){
        IPA.nav.update();
    }

    function create_navigation() {
        var whoami = IPA.whoami;
        var factory;

        if (whoami.hasOwnProperty('memberof_group') &&
            whoami.memberof_group.indexOf('admins') !== -1) {
            factory = IPA.admin_navigation;

        } else if (whoami.hasOwnProperty('memberof_rolegroup') &&
            whoami.memberof_rolegroup.length > 0) {
            factory = IPA.admin_navigation;

        } else {
            factory = IPA.self_serv_navigation;
        }

        return factory({
            container: $('#navigation'),
            content: $('#content')
        });
    }


    function init_on_win(data, text_status, xhr) {
        $(window).bind('hashchange', window_hashchange);

        var whoami = IPA.whoami;
        IPA.whoami_pkey = whoami.uid[0];
        $('#loggedinas strong').text(whoami.cn[0]);
        $('#loggedinas a').fragment(
            {'user-facet': 'details', 'user-pkey': IPA.whoami_pkey}, 2);

        IPA.nav = create_navigation();
        IPA.nav.create();
        IPA.nav.update();

        $('#login_header').html(IPA.messages.login.header);

        if (IPA.hbac_deny_rules  && IPA.hbac_deny_rules.count > 0){
            if (IPA.nav.name === 'admin'){
                IPA.hbac_deny_warning_dialog();
            }
        }
    }


    function init_on_error(xhr, text_status, error_thrown) {
        var container = $('#content').empty();
        container.append('<p>Error: '+error_thrown.name+'</p>');
        container.append('<p>'+error_thrown.message+'</p>');
    }

    IPA.init(null, null, init_on_win, init_on_error);

});
