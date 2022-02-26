/*

Ported from https://github.com/slush0/stratum-mining/blob/master/lib/merkletree.py

 */

var util = require('./util.js');

function calcRoot(hashes) {
    var result = merklebitcoin(hashes);
    //console.log(Object.values(result)[2].root);
    return Object.values(result)[2].root;
}

var MerkleTree = module.exports = function MerkleTree(data){

    function merkleJoin(h1, h2){
        var joined = Buffer.concat([h1, h2]);
        var dhashed = util.sha256d(joined);
        return dhashed;
    }

    function calculateSteps(data){
        var L = data;
        var steps = [];
        var PreL = [null];
        var StartL = 2;
        var Ll = L.length;

        if (Ll > 1){
            while (true){

                if (Ll === 1)
                    break;

                steps.push(L[1]);

                if (Ll % 2)
                    L.push(L[L.length - 1]);

                var Ld = [];
                var r = util.range(StartL, Ll, 2);
                r.forEach(function(i){
                    Ld.push(merkleJoin(L[i], L[i + 1]));
                });
                L = PreL.concat(Ld);
                Ll = L.length;
            }
        }
       return steps;
    }

    this.data = data;
    this.steps = calculateSteps(data);

}
MerkleTree.prototype = {
    withFirst: function(f){
        this.steps.forEach(function(s){
            f = util.sha256d(Buffer.concat([f, s]));
        });
        return f;
    }
};

exports.getRoot = function (rpcData, generateTxRaw) {
    hashes = [util.reverseBuffer(new Buffer(generateTxRaw, 'hex')).toString('hex')];
    rpcData.transactions.forEach(function (value) {
         if (value.txid !== undefined) {
             hashes.push(value.txid);
         } else {
             hashes.push(value.hash);
         }
     });
    if (hashes.length === 1) {
        return hashes[0];
    }
    var result = calcRoot(hashes);
    return result;
};