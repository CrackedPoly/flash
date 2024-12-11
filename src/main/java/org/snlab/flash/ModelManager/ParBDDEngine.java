package org.snlab.flash.ModelManager;

import org.snlab.jni.NanoBDD;
import java.math.BigInteger;

class ParTrieCode {
    long result;
    ParTrieCode left, right; // left: 1, right: 0

    public ParTrieCode(long result) {
        this.result = result;
        this.left = this.right = null;
    }

    public ParTrieCode buildLeft(NanoBDD bdd, long var) {
        if (this.left == null) {
            this.left = new ParTrieCode(bdd.and(result, var));
            bdd.ref(this.left.result);
        }
        return this.left;
    }

    public ParTrieCode buildRight(NanoBDD bdd, long nVar) {
        if (this.right == null) {
            this.right = new ParTrieCode(bdd.and(result, nVar));
            bdd.ref(this.right.result);
        }
        return this.right;
    }
}

public final class ParBDDEngine {
    public final long BDDFalse;
    public final long BDDTrue;
    private final NanoBDD bdd;
    private final long[] vars, nVars, svars, snVars;
    private final ParTrieCode dst, src;
    private final int varNum;
    public double opCnt;

    public ParBDDEngine(int size) {
        this.opCnt = 0;
        this.varNum = size;
        // In C++ NanoBDD, the table size is the number of ConcurrentLinkedList.
        // Based on singe-thread benchmark on **I2** dataset, setting this value too high
        // will cause more memory footprint, while setting it too low the computation takes
        // longer (longer linkedlist). So 10_000_000 is a good value (100_000_000 will double
        // memory usage, no perf improvement, 1_000_000 will lose 40% perf).
        this.bdd = new NanoBDD(1_000_000, 100_000, size + 8);
        this.BDDFalse = bdd.getFalse();
        this.BDDTrue = bdd.getTrue();
        this.vars = new long[size];
        this.nVars = new long[size];
        for (int i = 0; i < size; i++) {
            this.vars[i] = bdd.var(i);
            this.nVars[i] = bdd.nvar(i);
        }
        this.svars = new long[8];
        this.snVars = new long[8];
        for (int i = 0; i < 8; i++) {
            this.svars[i] = bdd.var(size + i);
            this.snVars[i] = bdd.nvar(size + i);
        }
        this.dst = new ParTrieCode(BDDTrue);
        this.src = new ParTrieCode(BDDTrue);
    }

    public long encodeIpv4(BigInteger ip, int prefix) {
        ParTrieCode ret = dst;
        for (int i = 0; i < prefix; i++) {
            if (ip.testBit( varNum- 1 - i)) {
                ret = ret.buildLeft(this.bdd, vars[i]);
            } else {
                ret = ret.buildRight(this.bdd, nVars[i]);
            }
        }
        return ref(ret.result);
    }

    public long encodeIpv4(BigInteger ip, int prefix, int srcIp, int srcSuffix) {
        ParTrieCode ret = dst;
        for (int i = 0; i < prefix; i++) {
            if (ip.testBit(varNum - 1 - i)) {
                ret = ret.buildLeft(this.bdd, vars[i]);
            } else {
                ret = ret.buildRight(this.bdd, nVars[i]);
            }
        }

        ParTrieCode tmp = src;
        for (int i = 0; i < srcSuffix; i ++) {
            if (((srcIp >> i) & 1) == 1) {
                tmp = tmp.buildLeft(this.bdd, svars[i]);
            } else {
                tmp = tmp.buildRight(this.bdd, snVars[i]);
            }
        }

        return ref(bdd.and(ret.result, tmp.result));
    }

    public long not(long var) {
        opCnt ++;
        return ref(bdd.not(var));
    }

    public long and(long var1, long var2) {
        opCnt ++;
        return ref(bdd.and(var1, var2));
    }

    public long or(long var1, long var2) {
        opCnt ++;
        return ref(bdd.or(var1, var2));
    }

    public long diff(long var1, long var2) {
        opCnt ++;
        return ref(bdd.diff(var1, var2));
    }

    public long ref(long var) {
        bdd.ref(var);
        return var;
    }

    public long deRef(long var) {
        bdd.deRef(var);
        return var;
    }
}
