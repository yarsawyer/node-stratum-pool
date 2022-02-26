var bignum = require('bignum');

var merkleTree = require('./merkleTree.js');
var transactions = require('./transactions.js');
var util = require('./util.js');


/**
 * The BlockTemplate class holds a single job.
 * and provides several methods to validate and submit it to the daemon coin
**/
var BlockTemplate = module.exports = function BlockTemplate(jobId, rpcData, poolAddressScript, extraNoncePlaceholder, reward, txMessages, recipients, network) {

    //private members

    var submits = [];

    var nTime = util.packUInt32BE(rpcData.curtime).toString('hex');

    function getMerkleHashes(steps) {
        return steps.map(function (step) {
            return step.toString('hex');
        });
    }

    function getTransactionBuffers(txs) {
        var txHashes = txs.map(function (tx) {
            if (tx.txid !== undefined) {
                return util.uint256BufferFromHash(tx.txid);
            }
            return util.uint256BufferFromHash(tx.hash);
        });
        return [null].concat(txHashes);
    }

    function getVoteData() {
        if (!rpcData.masternode_payments) return new Buffer([]);

        return Buffer.concat(
            [util.varIntBuffer(rpcData.votes.length)].concat(
                rpcData.votes.map(function (vt) {
                    return new Buffer(vt, 'hex');
                })
            )
        );
    }

    //public members

    this.rpcData = rpcData;
    this.jobId = jobId;


    this.target = rpcData.target ?
        bignum(rpcData.target, 16) :
        util.bignumFromBitsHex(rpcData.bits);

    this.difficulty = parseFloat((diff1 / this.target.toNumber()).toFixed(9));

    this.prevHashReversed = util.reverseBuffer(new Buffer(rpcData.previousblockhash, 'hex')).toString('hex');
    this.merkleRoot = merkleTree.getRoot(rpcData, this.genTxHash);
    this.txCount = this.rpcData.transactions.length + 1; // add total txs and new coinbase
    this.merkleRootReversed = util.reverseBuffer(new Buffer(this.merkleRoot, 'hex')).toString('hex');


    this.prevHashReversed = util.reverseByteOrder(new Buffer(rpcData.previousblockhash, 'hex')).toString('hex');
    if (rpcData.finalsaplingroothash) {
        this.finalsaplingroothashReversed = util.reverseByteOrder(new Buffer(rpcData.finalsaplingroothash, 'hex')).toString('hex');
    }
    if (rpcData.hashstateroot) {
        this.hashstaterootReversed = util.reverseBuffer(new Buffer(rpcData.hashstateroot, 'hex')).toString('hex');
    }
    if (rpcData.hashutxoroot) {
        this.hashutxorootReversed = util.reverseBuffer(new Buffer(rpcData.hashutxoroot, 'hex')).toString('hex');
    }
    this.transactionData = Buffer.concat(rpcData.transactions.map(function (tx) {
        return new Buffer(tx.data, 'hex');
    }));
    this.merkleTree = new merkleTree(getTransactionBuffers(rpcData.transactions));
    this.merkleBranch = getMerkleHashes(this.merkleTree.steps);
    this.generationTransaction = transactions.CreateGeneration(
        rpcData,
        poolAddressScript,
        extraNoncePlaceholder,
        reward,
        txMessages,
        recipients,
        network
    );

    this.serializeCoinbase = function (extraNonce1, extraNonce2) {
        return Buffer.concat([
            this.generationTransaction[0],
            extraNonce1,
            extraNonce2,
            this.generationTransaction[1]
        ]);
    };


    //https://en.bitcoin.it/wiki/Protocol_specification#Block_Headers
    this.serializeHeader = function (merkleRoot, nTime, nonce) {

        var headerSize;
        if (rpcData.version == 5 && rpcData.finalsaplingroothash) {
            headerSize = 112;
        /*} else if (rpcData.hashstateroot && rpcData.hashutxoroot) {
            headerSize = 181;
        */
        } else {
            headerSize = 80;
        }

        var header = new Buffer(headerSize);
        var position = 0;

        if (rpcData.version == 5 && rpcData.finalsaplingroothash) {
            header.write(rpcData.finalsaplingroothash, position, 32, 'hex');
            position += 32;
        }

        header.write(nonce, position, 4, 'hex');
        header.write(rpcData.bits, position += 4, 4, 'hex');
        header.write(nTime, position += 4, 4, 'hex');
        header.write(merkleRoot, position += 4, 32, 'hex');
        header.write(rpcData.previousblockhash, position += 32, 32, 'hex');
        header.writeUInt32BE(rpcData.version, position + 32);
        var header = util.reverseBuffer(header);
        return header;
    };

    this.serializeBlock = function (header, coinbase) {
        return Buffer.concat([
            header,

            util.varIntBuffer(this.rpcData.transactions.length + 1),
            coinbase,
            this.transactionData,

            getVoteData(),

            //POS coins require a zero byte appended to block which the daemon replaces with the signature
            new Buffer(reward === 'POS' ? [0] : [])
        ]);
    };

    this.serializeHeaderKawpow = function() {
        var header =  new Buffer(80);
        var position = 0;

        header.write(util.packUInt32BE(this.rpcData.height).toString('hex'), position, 4, 'hex'); // height 42-46
        header.write(this.rpcData.bits, position += 4, 4, 'hex'); // bits 47-50
        header.write(nTime, position += 4, 4, 'hex');                        // nTime          51-54
        header.write(this.merkleRoot, position += 4, 32, 'hex');                  // merkelRoot     55-87
        header.write(this.rpcData.previousblockhash, position += 32, 32, 'hex');  // prevblockhash  88-120
        header.writeUInt32BE(this.rpcData.version, position + 32, 4);                // version        121-153

        header = util.reverseBuffer(header);
        return header;
    };

    // join the header and txs together
    this.serializeBlockKawpow = function(header_hash, nonce, mixhash) {

        header = this.serializeHeader();
        var foo = new Buffer(40);

        foo.write(util.reverseBuffer(nonce).toString('hex'), 0, 8, 'hex');
        foo.write(util.reverseBuffer(mixhash).toString('hex'), 8, 32,'hex');

        buf = new Buffer.concat([
            header,
            foo,
            util.varIntBuffer(this.rpcData.transactions.length + 1),
            new Buffer(this.genTx, 'hex')
        ]);

        if (this.rpcData.transactions.length > 0) {
            this.rpcData.transactions.forEach(function (value) {
                tmpBuf = new Buffer.concat([buf, new Buffer(value.data, 'hex')]);
                buf = tmpBuf;
            });
        }
        return buf;
    };


    this.registerSubmit = function (extraNonce1, extraNonce2, nTime, nonce) {
        var submission = extraNonce1 + extraNonce2 + nTime + nonce;
        if (submits.indexOf(submission) === -1) {
            submits.push(submission);
            return true;
        }
        return false;
    };

    this.getOdoKey = function () {
        if (this.rpcData && this.rpcData.odokey !== undefined) {
            return this.rpcData.odokey;
        }
        return null;
    };

    this.getJobParams = function () {
        if (!this.jobParams) {
            this.jobParams = [
                this.jobId,
                this.prevHashReversed,
                this.generationTransaction[0].toString('hex'),
                this.generationTransaction[1].toString('hex'),
                this.merkleBranch,
                util.packInt32BE(this.rpcData.version).toString('hex'),
                this.rpcData.bits,
                util.packUInt32BE(this.rpcData.curtime).toString('hex'),
                true
            ];
            if (this.finalsaplingroothashReversed) {
                this.jobParams.push(this.finalsaplingroothashReversed);
            }
            /*if (this.hashstaterootReversed && this.hashutxorootReversed) {
                this.jobParams.push(this.hashstaterootReversed);
                this.jobParams.push(this.hashutxorootReversed);
                this.jobParams.push('0000000000000000000000000000000000000000000000000000000000000000ffffffff00');
            }
            */
        }
        return this.jobParams;
    };
};