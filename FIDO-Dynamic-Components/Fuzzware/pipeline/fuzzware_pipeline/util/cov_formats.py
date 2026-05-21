def dump_cov_plain(covered_bbs, out_path):
    with open(out_path, "w") as f:
        f.write("\n".join(map(lambda bb: "{:x}".format(bb), sorted(covered_bbs))))

def dump_cov_EZCOV(covered_bbs, out_path):
    out = "EZCOV VERSION: 1\n"
    for addr in covered_bbs:
        out += f"{hex(addr)}, 4, [ MAIN ]\n"

    with open(out_path, "w") as f:
        f.write(out)

def dump_cov_cartographer(covered_bbs, out_path):
    dump_cov_EZCOV(covered_bbs, out_path)
