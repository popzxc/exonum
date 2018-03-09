const Vue = require('vue');
const Router = require('vue-router');
const Validate = require('../plugins/validate');
const Notify = require('../plugins/notify');
const axios = require('../plugins/axios');
const AuthPage = require('../pages/AuthPage.vue');
const WalletPage = require('../pages/WalletPage.vue');

Vue.use(Router);
Vue.use(Validate);
Vue.use(Notify);
Vue.use(axios);

module.exports = new Router({
    routes: [
        {
            path: '/',
            name: 'home',
            component: AuthPage
        },
        {
            path: '/user',
            name: 'user',
            component: WalletPage
        }
    ]
});
