package org.snlab.flash.ModelManager;


import org.snlab.network.Port;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

public class ParConflictFreeChanges {
    private final ParBDDEngine bddEngine;
    private final HashMap<Port, Number> newPortToBdd;
    private final HashMap<Number, TreeMap<Integer, Port>> predToChanges;

    private int changeCnt;

    public ParConflictFreeChanges(ParBDDEngine bddEngine) {
        this.bddEngine = bddEngine;
        this.newPortToBdd = new HashMap<>();
        this.predToChanges = new HashMap<>();
        this.changeCnt = 0;
    }

    /**
     * A predicate deltaBdd changes its action oldPort to newPort.
     * This method does the 1st aggregation according to (oldPort => newPort) pair.
     */
    public void add(long deltaBdd, Port oldPort, Port newPort) {
        if (oldPort == newPort) {
            bddEngine.deRef(deltaBdd);
            return;
        }

        if (newPortToBdd.containsKey(newPort)) {
            Number t = newPortToBdd.get(newPort);
            long union = bddEngine.or(t.longValue(), deltaBdd);
            newPortToBdd.replace(newPort, union);
            bddEngine.deRef(t.longValue());
            bddEngine.deRef(deltaBdd);
        } else {
            newPortToBdd.put(newPort, deltaBdd);
        }
        changeCnt++;
    }

    /**
     * This method does the 2nd aggregation according to unique BDDs.
     * Notice the bddToChanges is null before invoking this method.
     */
    public void aggrBDDs() {
        for (Map.Entry<Port, Number> entry : newPortToBdd.entrySet()) {
            Number bdd = entry.getValue();
            Port port = entry.getKey();
            predToChanges.putIfAbsent(bdd, new TreeMap<>());
            predToChanges.get(bdd).put(port.getDevice().uid, port);
        }
    }

    public void merge(ParConflictFreeChanges t) {
        for (Map.Entry<Port, Number> entry : t.newPortToBdd.entrySet()) {
            this.add(entry.getValue().longValue(), null, entry.getKey());
        }
    }

    public void releaseBDDs() {
        for (Number bdd : newPortToBdd.values()) bddEngine.deRef(bdd.longValue());
    }

    public int aggr0Size() {
        return changeCnt;
    }

    public int aggr1Size() {
        return newPortToBdd.size();
    }

    public int aggr2Size() {
        return predToChanges.size();
    }

    /**
     * This method decides what can be used by others.
     * @return the changes after 2-step aggregation.
     */
    public HashMap<Number, TreeMap<Integer, Port>> getAll() {
        return predToChanges;
    }
}
