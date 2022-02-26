var events = require('events');
var crypto = require('crypto');

var bignum = require('bignum');

var hasher_kawpow = require('hasher-kawpow');

var util = require('./util.js');
var blockTemplate = require('./blockTemplate.js');



//Unique extranonce per subscriber
var ExtraNonceCounter = function (configInstanceId) {

    var instanceId = configInstanceId || crypto.randomBytes(4).readUInt32LE(0);
    var counter = instanceId << 27;

    this.next = function () {
        var extraNonce = util.packUInt32BE(Math.abs(counter++));
        return extraNonce.toString('hex');
    };

    this.size = 4; //bytes
};

//Unique job per new block template
var JobCounter = function () {
    var counter = 0;

    this.next = function () {
        counter++;
        if (counter % 0xffff === 0)
            counter = 1;
        return this.cur();
    };

    this.cur = function () {
        return counter.toString(16);
    };
};

/**
 * Emits:
 * - newBlock(blockTemplate) - When a new block (previously unknown to the JobManager) is added, use this event to broadcast new jobs
 * - share(shareData, blockHex) - When a worker submits a share. It will have blockHex if a block was found
**/
var JobManager = module.exports = function JobManager(options) {


    //private members

    var _this = this;
    var jobCounter = new JobCounter();

    var shareMultiplier = algos[options.coin.algorithm].multiplier;
    var emitErrorLog = function (text) { _this.emit('log', 'error', text); };

    //public members

    this.extraNonceCounter = new ExtraNonceCounter(options.instanceId);
    this.extraNoncePlaceholder = new Buffer('f000000ff111111f', 'hex');
    this.extraNonce2Size = this.extraNoncePlaceholder.length - this.extraNonceCounter.size;
    this.currentJob;
    this.validJobs = {};

    var hashDigest = algos[options.coin.algorithm].hash(options.coin);

    var coinbaseHasher = (function () {
        switch (options.coin.algorithm) {
            case 'keccak':
            case 'blake':
            case 'fugue':
            case 'groestl':
                if (options.coin.normalHashing === true)
                    return util.sha256d;
                else
                    return util.sha256;
            default:
                return util.sha256d;
        }
    })();


    var blockHasher = (function () {
        switch (options.coin.algorithm) {
            case 'scrypt':
                if (options.coin.reward === 'POS') {
                    return function (d) {
                        return util.reverseBuffer(hashDigest.apply(this, arguments));
                    };
                }
            case 'scrypt-og':
                if (options.coin.reward === 'POS') {
                    return function (d) {
                        return util.reverseBuffer(hashDigest.apply(this, arguments));
                    };
                }
            case 'scrypt-jane':
                if (options.coin.reward === 'POS') {
                    return function (d) {
                        return util.reverseBuffer(hashDigest.apply(this, arguments));
                    };
                }
            case 'scrypt-n':
            case 'sha1':
            case 'yespowerSUGAR':
            case 'yescryptR8G':
            case 'lyra2re2':
            case 'yespowerLTNCG':
            case 'yescryptR16':
            case 'yespowerTIDE':
                return function (d) {
                    return util.reverseBuffer(util.sha256d(d));
                };
            default:
                return function () {
                    return util.reverseBuffer(hashDigest.apply(this, arguments));
                };
        }
    })();

    this.updateCurrentJob = function (rpcData) {

        var tmpBlockTemplate = new blockTemplate(
            jobCounter.next(),
            rpcData,
            options.poolAddressScript,
            _this.extraNoncePlaceholder,
            options.coin.reward,
            options.coin.txMessages,
            options.recipients,
            options.network
        );

        _this.currentJob = tmpBlockTemplate;

        _this.emit('updatedBlock', tmpBlockTemplate, true);

        _this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;

    };

    //returns true if processed a new block
    this.processTemplate = function (rpcData) {

        /* Block is new if A) its the first block we have seen so far or B) the blockhash is different and the
           block height is greater than the one we have */
        var isNewBlock = typeof (_this.currentJob) === 'undefined';
        if (!isNewBlock && _this.currentJob.rpcData.previousblockhash !== rpcData.previousblockhash) {
            isNewBlock = true;

            //If new block is outdated/out-of-sync than return
            if (rpcData.height < _this.currentJob.rpcData.height)
                return false;
        }

        if (!isNewBlock) return false;

        var tmpBlockTemplate = new blockTemplate(
            jobCounter.next(),
            rpcData,
            options.poolAddressScript,
            _this.extraNoncePlaceholder,
            options.coin.reward,
            options.coin.txMessages,
            options.recipients,
            options.network
        );

        this.currentJob = tmpBlockTemplate;

        this.validJobs = {};
        _this.emit('newBlock', tmpBlockTemplate);

        this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;

        return true;

    };

    this.processShare = function (jobId, previousDifficulty, difficulty, extraNonce1, extraNonce2, nTime, nonce, ipAddress, port, workerName, versionMask) {
        var shareError = function (error) {
            
            _this.emit('share', {
                job: jobId,
                ip: ipAddress,
                worker: workerName,
                difficulty: difficulty,
                error: error[1]
            });
            return { error: error, result: null };
        };

        var submitTime = Date.now() / 1000 | 0;

        if (extraNonce2.length / 2 !== _this.extraNonce2Size)
            return shareError([20, 'incorrect size of extranonce2']);

        var job = this.validJobs[jobId];
        if (typeof job === 'undefined' || job.jobId != jobId) {
            return shareError([21, 'job not found']);
        }
        if (nTime.length !== 8) {
            return shareError([20, 'incorrect size of ntime']);
        }
        var nTimeInt = parseInt(nTime, 16);
        if (nTimeInt < job.rpcData.curtime || nTimeInt > submitTime + 7200) {
            return shareError([20, 'ntime out of range']);
        }
        if (nonce.length !== 8) {
            return shareError([20, 'incorrect size of nonce']);
        }
        if (!job.registerSubmit(extraNonce1, extraNonce2, nTime, nonce)) {
            return shareError([22, 'duplicate share']);
        }


        var extraNonce1Buffer = new Buffer(extraNonce1, 'hex');
        var extraNonce2Buffer = new Buffer(extraNonce2, 'hex');

        var coinbaseBuffer = job.serializeCoinbase(extraNonce1Buffer, extraNonce2Buffer);
        var coinbaseHash = coinbaseHasher(coinbaseBuffer);

        var merkleRoot = util.reverseBuffer(job.merkleTree.withFirst(coinbaseHash)).toString('hex');

        var headerBuffer = job.serializeHeader(merkleRoot, nTime, nonce, versionMask);
        var headerHash = hashDigest(headerBuffer, nTimeInt);
        var headerBigNum = bignum.fromBuffer(headerHash, { endian: 'little', size: 32 });

        var blockHashInvalid;
        var blockHash;
        var blockHex;

        var shareDiff = diff1 / headerBigNum.toNumber() * shareMultiplier;

        var blockDiffAdjusted = job.difficulty * shareMultiplier;

        blockHexInvalid = job.serializeBlock(headerBuffer, coinbaseBuffer).toString('hex');

        blockHashInvalid = blockHasher(headerBuffer, nTime).toString('hex');

        //Check if share is a block candidate (matched network difficulty)
        if (job.target.ge(headerBigNum)) {
            blockHex = job.serializeBlock(headerBuffer, coinbaseBuffer).toString('hex');
            blockHash = blockHasher(headerBuffer, nTime).toString('hex');
        }
        else {
            if (options.emitInvalidBlockHashes)
                blockHashInvalid = util.reverseBuffer(util.sha256d(headerBuffer)).toString('hex');

            //Check if share didn't reached the miner's difficulty)
            if (shareDiff / difficulty < 0.99) {

                //Check if share matched a previous difficulty from before a vardiff retarget
                if (previousDifficulty && shareDiff >= previousDifficulty) {
                    difficulty = previousDifficulty;
                }
                else {
                    return shareError([23, 'low difficulty share of ' + shareDiff]);
                }

            }
        }

        _this.emit('share', {
            job: jobId,
            ip: ipAddress,
            port: port,
            worker: workerName,
            height: job.rpcData.height,
            blockReward: job.rpcData.coinbasevalue,
            difficulty: difficulty,
            shareDiff: shareDiff.toFixed(8),
            blockDiff: blockDiffAdjusted,
            blockDiffActual: job.difficulty,
            blockHash: blockHash,
            blockHashInvalid: blockHashInvalid,
            blockHexInvalid: blockHexInvalid,
            blockHex: blockHex
        }, blockHex);

        return { result: true, error: null, blockHash: blockHash };
    };

    this.processKawpowShare = function (jobId, previousDifficulty, difficulty, miner_given_nonce, ipAddress, port, workerName, miner_given_header, miner_given_mixhash, extraNonce1) {
        var submitTime = Date.now() / 1000 | 0;

        var shareError = function (error) {
          _this.emit('share', {
              job: jobId,
              ip: ipAddress,
              worker: workerName,
              difficulty: difficulty,
              error: error[1]
          });
          return { error: error, result: null };
        };

        var job = this.validJobs[jobId];

        if (typeof job === 'undefined' || job.jobId != jobId)
          return shareError([20, 'job not found']);

        //calculate our own header hash, do not trust miner-given value
        var headerBuffer = job.serializeHeaderKawpow(); // 140 bytes, doesn't contain nonce or mixhash/solution
        var header_hash_buffer = util.reverseBuffer(util.sha256d(headerBuffer))
        var header_hash = header_hash_buffer.toString('hex');

        if (job.curTime < (submitTime - 600))
          return shareError([20, 'job is too old']);

        if (!isHexString(miner_given_header))
          return shareError([20, 'invalid header hash, must be hex']);

        if (header_hash != miner_given_header)
          return shareError([20, 'invalid header hash']);

        if (!isHexString(miner_given_nonce))
          return shareError([20, 'invalid nonce, must be hex']);

        if (!isHexString(miner_given_mixhash))
          return shareError([20, 'invalid mixhash, must be hex']);

        if (miner_given_nonce.length !== 16)
          return shareError([20, 'incorrect size of nonce, must be 8 bytes']);

        if (miner_given_mixhash.length !== 64)
          return shareError([20, 'incorrect size of mixhash, must be 32 bytes']);

        if (miner_given_nonce.indexOf(extraNonce1.substring(0,4)) !== 0)
          return shareError([24, 'nonce out of worker range']);

        if (!job.registerSubmit(header_hash.toLowerCase(), miner_given_nonce.toLowerCase()))
          return shareError([22, 'duplicate share']);

        var powLimit = algos.kawpow.diff; // TODO: Get algos object from argument
        var adjPow = powLimit / difficulty;
        if ((64 - adjPow.toString(16).length) === 0) {
            var zeroPad = '';
        }
        else {
            var zeroPad = '0';
            zeroPad = zeroPad.repeat((64 - (adjPow.toString(16).length)));
        }
        var target_share_hex = (zeroPad + adjPow.toString(16)).substr(0,64);

        var blockHashInvalid;
        var blockHash;
        var blockHex;

        var isValid = hasher_kawpow.verify(header_hash, miner_given_mixhash, miner_given_nonce, job.rpcData.height, target_share_hex, job.target_hex).split(" ");

        is_share = isValid[1]
        is_block = isValid[2]
        blockHashDigest = isValid[3]
        if (is_share === "false") {
            if (is_block === "false") {
                return shareError([20, 'kawpow validation failed']);
            }
        }

        // At this point, either share or block is true (or both)

        if (is_block === "true") {
            // Good block.
            blockHex = job.serializeBlockKawpow(new Buffer(header_hash, 'hex'), new Buffer(miner_given_nonce, 'hex'), new Buffer(miner_given_mixhash, 'hex')).toString('hex');
            blockHash = blockHashDigest;
        }
        var blockDiffAdjusted = job.difficulty * shareMultiplier
        var shareDiffFixed = undefined;

        if (blockHash !== undefined) {
            var headerBigNum = bignum.fromBuffer(blockHash, {endian: 'little', size: 32});
            var shareDiff = diff1 / headerBigNum.toNumber() * shareMultiplier;
            shareDiffFixed = shareDiff.toFixed(8);
        }
        _this.emit('share', {
                job: jobId,
                ip: ipAddress,
                port: port,
                worker: workerName,
                height: job.rpcData.height,
                blockReward: job.rpcData.coinbasevalue,
                difficulty: difficulty,
                shareDiff: shareDiffFixed,
                blockDiff: blockDiffAdjusted,
                blockDiffActual: job.difficulty,
                blockHash: blockHash,
                blockHashInvalid: blockHashInvalid
              }, blockHex);

        return {result: true, error: null, blockHash: blockHash};
      }

};
JobManager.prototype.__proto__ = events.EventEmitter.prototype;
