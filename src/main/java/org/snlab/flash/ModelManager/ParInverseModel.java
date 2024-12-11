package org.snlab.flash.ModelManager;


import org.snlab.flash.ModelManager.Ports.PersistentPorts;
import org.snlab.flash.ModelManager.Ports.Ports;
import org.snlab.network.Device;
import org.snlab.network.Network;
import org.snlab.network.Port;
import org.snlab.network.Rule;

import java.util.*;

public class ParInverseModel {
    public final ParBDDEngine bddEngine;
    private int size = 32; // length of packet header

    private final HashMap<Rule, Number> ruleToBddMatch;
    private final HashMap<Device, IndexedRules> deviceToRules; // FIB snapshots
    public HashMap<Ports, Number> portsToPredicate; // network inverse model

    private double s1 = 0, s1to2 = 0, s2 = 0, sports = 0;

    public ParInverseModel(Network network) {
        this(network, new ParBDDEngine(32), new PersistentPorts());
    }

    public ParInverseModel(Network network, int size) {
        this(network, new ParBDDEngine(size), new PersistentPorts());
        this.size = size;
    }

    public ParInverseModel(Network network, Ports base) {
        this(network, new ParBDDEngine(32), base);
    }

    public ParInverseModel(Network network, int size, Ports base) {
        this(network, new ParBDDEngine(size), base);
        this.size = size;
    }

    public ParInverseModel(Network network, ParBDDEngine bddEngine, Ports base) {
        this.bddEngine = bddEngine;
        this.deviceToRules = new HashMap<>();
        this.ruleToBddMatch = new HashMap<>();

        // Relabel every device as the index used by Ports, starting from 0
        for (Device device : network.getAllDevices()) this.deviceToRules.put(device, new IndexedRules());

        // Each device has a default rule with default action.
        ArrayList<Port> key = new ArrayList<>();
        for (Device device : network.getAllDevices()) {
            Port p = device.getPort("default");
            key.add(p);
            Rule rule = new Rule(device, 0, 0, -1, p);
            ruleToBddMatch.put(rule, bddEngine.BDDTrue);
            deviceToRules.get(device).insert(rule, size);
        }

        // The only one EC takes default actions.
        this.portsToPredicate = new HashMap<>();
        this.portsToPredicate.put(base.create(key, 0, key.size()), bddEngine.BDDTrue);
    }

    public ParConflictFreeChanges insertMiniBatch(List<Rule> insertions) {
        return this.miniBatch(insertions, new ArrayList<>());
    }

    /**
     * Notates current data-plane (flow rules) as f, consider transition to f'
     * @param insertions f' - f
     * @param deletions  f - f'
     * @return the change \chi
     */
    public ParConflictFreeChanges miniBatch(List<Rule> insertions, List<Rule> deletions) {
        s1 -= System.nanoTime();
        HashSet<Rule> inserted = new HashSet<>();
        HashSet<Rule> deleted = new HashSet<>(deletions);
        for (Rule rule : insertions) {
            if (deleted.contains(rule)) {
                deleted.remove(rule);
                continue;
            }
            inserted.add(rule);
            ruleToBddMatch.put(rule, bddEngine.encodeIpv4(rule.getMatch(), rule.getPrefix(), rule.getSrc(), rule.getSrcSuffix()));
            deviceToRules.get(rule.getDevice()).insert(rule, size);
        }
        for (Rule rule : deleted) deviceToRules.get(rule.getDevice()).remove(rule, size);

        ParConflictFreeChanges ret = new ParConflictFreeChanges(bddEngine);
        // Notice recomputing the #ECs can be faster than rule-deleting if many rules are deleted (especially when all rules are deleted).
        // For the purpose of evaluation, we did not go through such short-cut.
        for (Rule rule : deleted) identifyChangesDeletion(rule, ret);
        for (Rule rule : inserted) identifyChangesInsert(rule, ret);
        s1 += System.nanoTime();
        return ret;
    }

    private long getHit(Rule rule) {
        long hit = bddEngine.ref(ruleToBddMatch.get(rule).longValue());
        for (Rule r : deviceToRules.get(rule.getDevice()).getAllOverlappingWith(rule, size)) {
            if (!ruleToBddMatch.containsKey(r)) continue;

            if (r.getPriority() > rule.getPriority()) {
                long newHit = bddEngine.diff(hit, ruleToBddMatch.get(r).longValue());
                bddEngine.deRef(hit);
                hit = newHit;
            }

            if (hit == BDDEngine.BDDFalse) break;
        }
        return hit;
    }

    /**
     * @param rule an inserted rule
     * @param ret  the pointer to the value returned by this function
     */
    private void identifyChangesInsert(Rule rule, ParConflictFreeChanges ret) {
        long hit = getHit(rule);
        if (hit != BDDEngine.BDDFalse) {
            s1 += System.nanoTime();
            s1to2 -= System.nanoTime();
            ret.add(hit, null, rule.getOutPort());
            s1to2 += System.nanoTime();
            s1 -= System.nanoTime();
        } else {
            bddEngine.deRef(hit);
        }
    }

    private void identifyChangesDeletion(Rule rule, ParConflictFreeChanges ret) {
        if (ruleToBddMatch.get(rule) == null) return; // cannot find the rule to be removed

        IndexedRules targetNode = deviceToRules.get(rule.getDevice());
        ArrayList<Rule> sorted = targetNode.getAllOverlappingWith(rule, size);
        Comparator<Rule> comp = (Rule lhs, Rule rhs) -> rhs.getPriority() - lhs.getPriority();
        sorted.sort(comp);

        long hit = getHit(rule);
        for (Rule r : sorted) {
            if (r.getPriority() < rule.getPriority()) {
                long intersection = bddEngine.and(ruleToBddMatch.get(r).longValue(), hit);

                long newHit = bddEngine.diff(hit, intersection);
                bddEngine.deRef(hit);
                hit = newHit;

                if (intersection != BDDEngine.BDDFalse && r.getOutPort() != rule.getOutPort()) {
                    s1 += System.nanoTime();
                    s1to2 -= System.nanoTime();
                    ret.add(intersection, rule.getOutPort(), r.getOutPort());
                    s1to2 += System.nanoTime();
                    s1 -= System.nanoTime();
                } else {
                    bddEngine.deRef(intersection);
                }
            }
        }
        targetNode.remove(rule, size);
        bddEngine.deRef(ruleToBddMatch.get(rule).longValue());
        ruleToBddMatch.remove(rule);
        bddEngine.deRef(hit);
    }


    private void insertPredicate(HashMap<Ports, Number> newPortsToPreds, Ports newPorts, Number predicate) {
        if (newPortsToPreds.containsKey(newPorts)) {
            Number t = newPortsToPreds.get(newPorts);
            newPortsToPreds.replace(newPorts, bddEngine.or(t.longValue(), predicate.longValue()));
            bddEngine.deRef(predicate.longValue());
            bddEngine.deRef(t.longValue());
        } else {
            newPortsToPreds.put(newPorts, predicate);
        }
    }

    /**
     * Fast Inverse Model Transformation
     * Updates and returns all transferred ECs.
     *
     * @param conflictFreeChanges -
     * @return -
     */
    public HashSet<Number> update(ParConflictFreeChanges conflictFreeChanges) {
        s1to2 -= System.nanoTime();
        conflictFreeChanges.aggrBDDs();
        s1to2 += System.nanoTime();


        s2 -= System.nanoTime();
        HashSet<Number> transferredECs = new HashSet<>();

        for (Map.Entry<Number, TreeMap<Integer, Port>> entryI : conflictFreeChanges.getAll().entrySet()) {
            Number delta = entryI.getKey();
            bddEngine.ref(delta.longValue());

            HashMap<Ports, Number> newPortsToPreds = new HashMap<>();
            for (Map.Entry<Ports, Number> entry : portsToPredicate.entrySet()) {
                Ports ports = entry.getKey();
                Number predicate = entry.getValue();
                if (delta.longValue() == bddEngine.BDDFalse) { // change already becomes empty
                    insertPredicate(newPortsToPreds, ports, predicate);
                    continue;
                }

                long intersection = bddEngine.and(predicate.longValue(), delta.longValue());
                if (intersection == bddEngine.BDDFalse) { // EC is not affected by change
                    insertPredicate(newPortsToPreds, ports, predicate);
                    bddEngine.deRef(intersection);
                    continue;
                } else {
                    // clean up the intermediate variables
                    long t = bddEngine.diff(delta.longValue(), intersection);
                    bddEngine.deRef(delta.longValue());
                    delta = t;
                }


                if (intersection != predicate.longValue()) {
                    // EC is partially affected by change, which causes split
                    // transferredECs.add(intersection);
                    insertPredicate(newPortsToPreds, ports, bddEngine.diff(predicate.longValue(), intersection));
                }
                // The intersection is transferred
                transferredECs.add(intersection);
                sports -= System.nanoTime();
                Ports portsT = ports.createWithChanges(entryI.getValue());
                sports += System.nanoTime();
                insertPredicate(newPortsToPreds, portsT, intersection);
                bddEngine.deRef(predicate.longValue());
            }

            bddEngine.deRef(delta.longValue());
            portsToPredicate = newPortsToPreds;
        }
        s2 += System.nanoTime();

        // Manually deref BDDs used by Changes since its deconstructor doesn't handle this.
        conflictFreeChanges.releaseBDDs();
        return transferredECs;
    }

    public HashMap<Port, HashSet<Number>> getPortToPredicate() {
        HashMap<Port, HashSet<Number>> ret = new HashMap<>();
        for (Map.Entry<Ports, Number> entry : portsToPredicate.entrySet())
            for (Port p : entry.getKey().getAll()) {
                ret.putIfAbsent(p, new HashSet<>());
                ret.get(p).add(entry.getValue());
            }
        return ret;
    }

    public int predSize() {
        return this.portsToPredicate.size();
    }

    public double printTime(int size) {
        long nsToUsPU = 1000L * size;
        if (size == 0)  nsToUsPU = 1000L * 1000L;
        System.out.println("    Stage 1 (Update Block Computation) " + (s1 / nsToUsPU) + " us per-update");
        System.out.println("    Converting to Conflict-free Update Block " + (s1to2 / nsToUsPU) + " us per-update");
        System.out.println("    Stage 2 (Model Update) " + (s2 / nsToUsPU) + " us per-update");
        System.out.println("    Ports " + (sports / nsToUsPU) + " us per-update");
        return s1 + s1to2 + s2;
    }
}
