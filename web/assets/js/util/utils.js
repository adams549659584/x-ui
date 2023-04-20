
class HttpUtil {
    static _handleMsg(msg) {
        if (!(msg instanceof Msg)) {
            return;
        }
        if (msg.msg === "") {
            return;
        }
        if (msg.success) {
            Vue.prototype.$message.success(msg.msg);
        } else {
            Vue.prototype.$message.error(msg.msg);
            if (msg.msg == '登录时效已过，请重新登录') {
                setTimeout(() => {
                    Vue.prototype.$message.warning("自动跳转至登录页...")
                    setTimeout(() => { window.location.reload() }, 3000)
                }, 2000)
            }
        }
    }

    static _respToMsg(resp) {
        const data = resp.data;
        if (data == null) {
            return new Msg(true);
        } else if (typeof data === 'object') {
            if (data.hasOwnProperty('success')) {
                return new Msg(data.success, data.msg, data.obj);
            } else {
                return data;
            }
        } else {
            return new Msg(false, 'unknown data:', data);
        }
    }

    static async get(url, data, options) {
        let msg;
        try {
            const resp = await axios.get(url, data, options);
            msg = this._respToMsg(resp);
        } catch (e) {
            msg = new Msg(false, e.toString());
        }
        this._handleMsg(msg);
        return msg;
    }

    static async post(url, data, options) {
        let msg;
        try {
            const resp = await axios.post(url, data, options);
            msg = this._respToMsg(resp);
        } catch (e) {
            msg = new Msg(false, e.toString());
        }
        this._handleMsg(msg);
        return msg;
    }

    static async postWithModal(url, data, modal) {
        if (modal) {
            modal.loading(true);
        }
        const msg = await this.post(url, data);
        if (modal) {
            modal.loading(false);
            if (msg instanceof Msg && msg.success) {
                modal.close();
            }
        }
        return msg;
    }
}

class PromiseUtil {

    static async sleep(timeout) {
        await new Promise(resolve => {
            setTimeout(resolve, timeout)
        });
    }

}

const seq = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z'
];

const shortIdSeq = [
    'a', 'b', 'c', 'd', 'e', 'f',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
];

// for i in $(seq 1 20); do ./xray-linux-amd64 x25519 >> key.log; done
const x25519Map = new Map(
    [
        ['SM6xgOhADFR1eMPUJfq9CuBabvweJzQFylHcY6VZsks', 'CzIbR5_2L_OmXfU13Wn1E-fHEXPf9ecZi2rydF7OSg4'],
        ['SEvKnyTYJqEzNfFJyAJkQtWkQdALZ5vgDwCixgQ7HUA', 'XmLK2ath08m5FeY9DksTUMMxCUsuGwQJcnKV7b7x50k'],
        ['IBww0FC05uWEn80HNo603kuq_K3P0JR83C-ZAJixtUA', 'JLNDKPtKyWxTnMqYmF14IeSXrkAKrw4v9arPHc0axBw'],
        ['CDdaEJpkrVRnY7-1bVYB9cFc3pfjOid0BMBu-tg3E18', 'R7VA1toWUYdEV1sYcUrzFaxzNdp8EkHWY7KdoRT3P20'],
        ['IJwLjF-QhMEWNqQhci6bq0gNX4b99afaAaYQxhzZEkE', 'Rqr1b7TD3SkrLDjVfC4FithvkJ2pX0uZ9_BDFiFXPyY'],
        ['eAhHmgivDuMb8sZT8AD0bWGzuA-bllaM9WDCL6UexkU', 'QImPRWZSUqCaaycgpYdKf4oOe6s495a6-AJ5AhJLwR4'],
        ['eCbnb53nSoduTsov5bL3_wumt75BOhWrnAI4XQ22b3Y', 'OBSkG8uoONJKqAfp_dChdz1pXoqWwg2Pjp3ZKa1g83Y'],
        ['AEWjtZoCeMBNqktdRA8I0gJrxgQB1BeVnQXs10iA8Xw', 'xIEbkFU5wOZYChruqZ1WYqZKv7g9KkCwbYf_0n5vIH4'],
        ['KHkpsqq5AdUkUWgu4AXodUtccAP59w0Of1lc5q3eE3c', 'gDLcqebpmRfeuRf6A71kMqsCQsElDFlGJPgWN0gY8n0'],
        ['UByWHtzebzFwHInD2NSzlkRcX9uIXKqkD3hTL49ZKHo', 'rr8FZzdQECFLuC6p7QBcpSQIZPO1PLzuxXOjomA0bmo'],
        ['MHEktItsE7pGOUP6wzgRjZ9Mv-9BMjO4W3kvNni9Z3A', 'KJq0ZiwtVK_x_Kn-Vtx8v6ZOFjK2FROvRzSGS1e56zg'],
        ['KF0k2GVKGcaz4mgZvo4OBwxFD07g8kdJyVItUXkDVV8', 'cDpTAV6mOOcVlfDZTaaT_oYrEQxfCKc3UMnYPnRCrAU'],
        ['CNTrEFOXVKmrHzVIJpBgkqeX-NvGgOQ331jntjvCqlU', '8KJp6czLUta2Amh3QV-mkgan_HvBwduQ85wqLlqB5jk'],
        ['qPzm3DVzKHoNSDKUvi2OwhoE5fev6fi6b5-NtfW2CXY', 'KReiSMnFs9m9vqqa9rtANYgsidODKPNIlMggu8gj7GM'],
        ['YHRb76c6dd9_enZ7IigVT6XiaZw5DzkRJA_T_BakemM', 'ZXbNIYE73D5iRqTbksoz-H9P5XufpV1_ZDPhLV5on2I'],
        ['MCN3z7Hl-Fy3EjmAX0squ84r50furrc1aKHPtSeEe3M', 'OQWkmjxBSDHu0zU2XfvbSJ4skJtfgW9DsOt25D2ra0Y'],
        ['4MGhdgF_2PuqdypB7oH6iA-ZPaauOZDpaMftYg48-VU', 'Spa7Ag0RUet70_EgwYwqefbw_3wZ0_ay1Ezk9sipWRI'],
        ['-BTGxw8M7Td9Wl6jfcr-T9kQwcUeR_tq8gwIe_P9In4', 'Q5sKRgJGhFMiqSibS8HOwYVGnA6LzsjULeMtlzLzoFg'],
        ['yJBmql9jeSZpjjPFGXUE2cKDCF54g3RD1wjN1_sNWn4', 'UXg23bcubiAr528B7p4Y6J8UDoknfz27I9o52QqWDB0'],
        ['4KFTwXoEUKSzthMCy1Po_zNWkzqxkibmeyUyHLeLq3Y', 'SovoswfB9c_84_28KB97v4Ocz07nNEITnyDKS5wkjnk'],
        ['WMSANc5cSR7chxL-JGkIwfT7QnKaA1TdPB9WyGYIsnU', 'XziIICPwX-twOXCYtdyWKnsl4G-r7bX6avMRiJfiEgk'],
        ['oAWvZGiFvA4uQ4nSJXrhek_5uZ457hc12EDqYdf--n0', 'CtUsUxT9ZjzVtOAeLTPr2m67UZ-VCPWOzRwJaKLziBM'],
        ['CCMD0rjfa7lT87PuPlV-4LU7frbhTud-3UeHs-3w0FQ', 'F5tpw5MMwlWVIliYJqYKFg6QLdGNNUN-DsUfBz5tDys'],
        ['MCXaKuO8l7t6CxIiBt-xsW5-aiU-BBm3GBQn0wh4904', 'NZnZpOTC2kxnAzmxl0d86DU_FL2DWdv9bsL_FEp8Qi0'],
        ['GLjy21rGAp4h2a14V4TGuAeVPvY1xVHxgrMB58yfvVw', 'sKLbnl35UV0OUfZecbrJmHJGmDAUHrfKldgttVStChs'],
        ['8L6FlCf7NlT0GL9htWCbOt81xlyCDAKauPyAiDLjll8', 'QRnxYRmcI39duzDmI-hM_2bxhCmKLFWQQcUB9iArEmc'],
        ['mA7nVhSa_8p0rKhJQGJMdyP_yoGJJDxdDFxmGfKaOUE', 'YKsQLFTEdIGlhhurWSWYW8TvazDrZgensA8O1HvqICw'],
        ['IFZbBPa_dVCdMl4dl96xHHf97Kc7RTRaHA6JmRtiomo', 'd3bq7mbEK_i2JYwQd-oWb-OJr27LUj5WJ0tPvYGoNB0'],
        ['iFdEGkFSq0ZmD1e7Cf6VElHAjmyEHzMKNT5nlJ0miGU', '9-biYIbF3kd48r106BUYFS7jMtPvYicGV6pi3ZNgiho'],
        ['eDbncbU1bZRbfGmDf9V8zpILl9Pgk5hvVaQehivK2kY', 'CapaS8NnuNZ5jgg3zmMsgmTtPq_5PEtJd50BStHotFM'],
        ['iA8SrhYpzd9-3KJzIyKWhuywzASf62SigvuDNRh561k', 'F6xzQaqs43aET83AFVxuznUIm13kjNdQA2G5RkvuDwU'],
        ['2OoC2mIq3BOPlfq5usXf-9817J8VJzinpCeiPhLUjWg', 'f8U3K-nJyCVqJHn_JkpK064drFlzP6z3KY4GIxaqnwo'],
        ['0MMtWCYuuXgebbhsW2c32CUysbtN8QbYaXjEfG-_4nY', 'K1EcPcWH38gx6yK7FgEjRERzEIFVJpartUwue0MOUUM'],
        ['GOe2s-ieQ2PYpN2TkReQ0SUActSW1JB4ikBPiuKQI18', '0Xyik21HjpxMsypZsie6lAFJZ-NeXdBBGihsOsJ9_gM'],
        ['qKvCWGYSzTxD9KTZRjTc4nxpkoUMogIJgfPtiRRHSX0', 'YWKToxXLlIjt8Q8ESbyfvDMnPbbRREnVA3xRyfAMBxA'],
        ['EFACS-ludWiG-mWMH9pKsa3yO38CbETZ3lSu3xweTEg', 'JO2AZ_WZYok6dFAulZVSSI3VUS08PonJpP0K1Eo3zzw'],
        ['qFUES9hFn3J93YYiDSmVB_p7ycUyNNm9h6pdRDd-bUY', 'Jk9hsGD7Ax0WzcNQFQ8mlR40lZ_MADhWnyjHmzmq_Gs'],
        ['iFy8vjw_IF3GqeEM8h2hM7tkjXVtyY34GGHbiSNpT0Q', '0oOWG9fpWTvyPjdiO54R2YV7TCyRSxiRk3WtZtrlSnU'],
        ['OBwA05sj2anBrCbgna1U7kniCe8mqnyVd__ggQPwsF0', '-y7u51roWzhh0YftU4A9issvK0yaaH-_kZ8eoif590U'],
        ['CGN27K3YewYodEfw_EbU91qAygviPtFGhdQDvNXmGX8', 'oEtdGUDTzwKLFP831Q2BmTMTAcCQmi9_JNFQm1XPrGc'],
    ]
);

class RandomUtil {

    static randomIntRange(min, max) {
        return parseInt(Math.random() * (max - min) + min, 10);
    }

    static randomInt(n) {
        return this.randomIntRange(0, n);
    }

    static randomSeq(count) {
        let str = '';
        for (let i = 0; i < count; ++i) {
            str += seq[this.randomInt(62)];
        }
        return str;
    }

    static randomShortIdSeq(count) {
        let str = '';
        for (let i = 0; i < count; ++i) {
            str += shortIdSeq[this.randomInt(16)];
        }
        return str;
    }

    static randomLowerAndNum(count) {
        let str = '';
        for (let i = 0; i < count; ++i) {
            str += seq[this.randomInt(36)];
        }
        return str;
    }

    static randomMTSecret() {
        let str = '';
        for (let i = 0; i < 32; ++i) {
            let index = this.randomInt(16);
            if (index <= 9) {
                str += index;
            } else {
                str += seq[index - 10];
            }
        }
        return str;
    }

    static randomEmail() {
        let str = '';
        str = this.randomSeq(4) + ".love@xray.com";
        return str;
    }

    static randomUUID() {
        let d = new Date().getTime();
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            let r = (d + Math.random() * 16) % 16 | 0;
            d = Math.floor(d / 16);
            return (c === 'x' ? r : (r & 0x7 | 0x8)).toString(16);
        });
    }

    static randowShortId() {
        let str = '' + ',';
        str += (this.randomShortIdSeq(2) + ',')
        str += (this.randomShortIdSeq(4) + ',')
        str += (this.randomShortIdSeq(6) + ',')
        str += this.randomShortIdSeq(8)
        return str;
    }

    static randomX25519PrivateKey() {
        let num = x25519Map.size;
        let index = this.randomInt(num);
        let cntr = 0;
        for (let key of x25519Map.keys()) {
            if (cntr++ === index) {
                return key;
            }
        }
    }

    static randomX25519PublicKey(key) {
        return x25519Map.get(key)
    }
}

class ObjectUtil {

    static getPropIgnoreCase(obj, prop) {
        for (const name in obj) {
            if (!obj.hasOwnProperty(name)) {
                continue;
            }
            if (name.toLowerCase() === prop.toLowerCase()) {
                return obj[name];
            }
        }
        return undefined;
    }

    static deepSearch(obj, key) {
        if (obj instanceof Array) {
            for (let i = 0; i < obj.length; ++i) {
                if (this.deepSearch(obj[i], key)) {
                    return true;
                }
            }
        } else if (obj instanceof Object) {
            for (let name in obj) {
                if (!obj.hasOwnProperty(name)) {
                    continue;
                }
                if (this.deepSearch(obj[name], key)) {
                    return true;
                }
            }
        } else {
            return obj.toString().indexOf(key) >= 0;
        }
        return false;
    }

    static isEmpty(obj) {
        return obj === null || obj === undefined || obj === '';
    }

    static isArrEmpty(arr) {
        return !this.isEmpty(arr) && arr.length === 0;
    }

    static copyArr(dest, src) {
        dest.splice(0);
        for (const item of src) {
            dest.push(item);
        }
    }

    static clone(obj) {
        let newObj;
        if (obj instanceof Array) {
            newObj = [];
            this.copyArr(newObj, obj);
        } else if (obj instanceof Object) {
            newObj = {};
            for (const key of Object.keys(obj)) {
                newObj[key] = obj[key];
            }
        } else {
            newObj = obj;
        }
        return newObj;
    }

    static deepClone(obj) {
        let newObj;
        if (obj instanceof Array) {
            newObj = [];
            for (const item of obj) {
                newObj.push(this.deepClone(item));
            }
        } else if (obj instanceof Object) {
            newObj = {};
            for (const key of Object.keys(obj)) {
                newObj[key] = this.deepClone(obj[key]);
            }
        } else {
            newObj = obj;
        }
        return newObj;
    }

    static cloneProps(dest, src, ...ignoreProps) {
        if (dest == null || src == null) {
            return;
        }
        const ignoreEmpty = this.isArrEmpty(ignoreProps);
        for (const key of Object.keys(src)) {
            if (!src.hasOwnProperty(key)) {
                continue;
            } else if (!dest.hasOwnProperty(key)) {
                continue;
            } else if (src[key] === undefined) {
                continue;
            }
            if (ignoreEmpty) {
                dest[key] = src[key];
            } else {
                let ignore = false;
                for (let i = 0; i < ignoreProps.length; ++i) {
                    if (key === ignoreProps[i]) {
                        ignore = true;
                        break;
                    }
                }
                if (!ignore) {
                    dest[key] = src[key];
                }
            }
        }
    }

    static delProps(obj, ...props) {
        for (const prop of props) {
            if (prop in obj) {
                delete obj[prop];
            }
        }
    }

    static execute(func, ...args) {
        if (!this.isEmpty(func) && typeof func === 'function') {
            func(...args);
        }
    }

    static orDefault(obj, defaultValue) {
        if (obj == null) {
            return defaultValue;
        }
        return obj;
    }

    static equals(a, b) {
        for (const key in a) {
            if (!a.hasOwnProperty(key)) {
                continue;
            }
            if (!b.hasOwnProperty(key)) {
                return false;
            } else if (a[key] !== b[key]) {
                return false;
            }
        }
        return true;
    }

}