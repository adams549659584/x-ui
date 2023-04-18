
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

const x25519Map = new Map(
    [
        ['ME5TP2l9tYbgeGRxf05_LEiXYFOyeqn3TMRju79VWVc', "g1f1wLjim5gOVGnI5LGUV0dL4iFXPoiepOPZfSxJe14"],
        ['MGpadXgOh0X_ylHa8y4OO_0QdRIVEXgwCdeJ3wkFUEo', "S-g0oP36DShii1uPOnZDSEhp_wQghX6h68PgMivOmD4"],
        ['SMUNw4bzoh4YNVNqjKhROUJNm94W0dV0YWUqwUL7WWc', "g-oxbqigzCaXqARxuyD2_vbTYeMD9zn8wnTo02S69QM"],
        ['qETaaytJUuSHU0Bp8nhYL9-f8prNlCthvukmR29Pqk4', "9rx7JwMO-KRZZEM9TQBO19BOAmmGjJyjN86ll2J7uVc"],
        ['YFHgoHbN8fBzOCjmcQeAPK7KhfwN8wbxfoarjSFw_mg', 'Z3ZGnAOdKkzJ07gR_7_0k9_iTTFP6paDOrqx1rN2LU4'],
        ['oKVwj79wHXjWIFUq0qkmdHXusmr4fQYPNeNM--6f03g', 'rYH4wPTVzSwtpXgI3U7YxppIP6oudD-425vT7pyhj1w'],
        ['cAtmGR6xSiqLXpogMs25jnbSqxLLL6a3Q9DseqlSQV4', '4comh-7Jm_wZXJQ5QiLSCbVGQIbMUzHUIBdb0aFtLzM'],
        ['SKY-V28aSzTux3jRMYf_0P_KiDm7ktd0ULu7_l-rxWI', 'UtL7E0Gmxj3X5JdcPAutpTRKo7K2hugkR0vwk2XroUM'],
        ['YAs6KwZahtKsCG7gRUsKi8d9DfVTzCz_z5jLsvE-r1U', 'IiuIighvDsor2v-vb5s3IJbNiqwLw568auiqoXxc7FM'],
        ['MCCwTFk3CxRaP4H6wrPI4tUQXBvq5ba_dyVBpLG06FI', 'rwpbqas_HY8knlW0fFSIeUrjgBXHBzSNboflsLD8elA'],
        ['YOYUy0H_t-GZKTYJ6eVB8iDd_L_CyYmXQe_-rCP7_VM', 'W9BjX6YmCIVsjhKMlz233Yoe0xcf0SVHfvPKqbf3vCg'],
        ['GD1oTwgOIh3hBuSXb2OnPtCx0a8_FwBBZh_Gk840qGU', 'cDaDzPr3PlS3NM8lreHZbdo-Mhqz8vMBzMSkHXhGIUA'],
        ['WOnYR0Jwy7MAzrz5vpWBDxr6thXjFk0rv_gCHGWEFHk', 'R2gKMF0Tetlnesc1pPkZH9NaOeehw-f5_U9JKG_cLjU'],
        ['uCDvXj-LVmgJa3IoR-VQkInucVyZO0AtF0IYUPLgPUY', 'UK7qxWWGfRQcQfwaGpHnqmmqqJBut4jxve8AeDDJ2UI'],
        ['6OMBI97diaQ66QNbIP0ae00t8i_SaEJ5gsv8oZ2ncks', 'qhTzYYIgBzDLNYR79oxftqdo1kzL-1_hGJKfqrOliCY'],
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