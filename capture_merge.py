#!/usr/bin/env python3
"""Junta as duas metades de uma sessão gravada, em ordem de tempo.

O relay grava um arquivo por conexão, e cada um tem uma direção só: o que
AQUELE console mandou. Isso é consequência de como o relay funciona -- cada
thread lê de um socket e escreve no outro, então ninguém vê as duas pontas.

Esta ferramenta remonta a conversa: lê os dois arquivos, ordena tudo pela
hora absoluta de cada pedaço e escreve a sequência intercalada. É o que um
conversor precisa como entrada, e é deliberadamente o fim da linha aqui --
NÃO existe conversão para replay do Pokémon Stadium 2 / Kin Gin neste
repositório, porque o formato do replay não está documentado aqui. Inventar
um palpite seria pior que não ter: passaria por pronto.

Uso:
    capture_merge.py A.jsonl B.jsonl              # texto legível
    capture_merge.py A.jsonl B.jsonl --raw dir/   # dois .bin, um por direção

Um aviso sobre a ordem: ela vem do relógio do servidor, com precisão de
microssegundos, e o relay grava DEPOIS de repassar ao par. Para dois pedaços
que saíram quase juntos, a ordem entre eles é a ordem em que o relay os
tratou, não necessariamente a ordem em que os consoles os produziram. Para
uma troca por turnos isso não muda nada; se algum dia importar, o lugar de
resolver é o relay, com um contador por sessão, e não aqui.
"""

import sys
import json
import base64
import os


def carregar(caminho):
    """Um arquivo de captura como (cabeçalho, [(hora, bytes)], fim)."""
    cabecalho = None
    pedacos = []
    fim = None
    truncado = False
    with open(caminho, encoding="utf-8") as f:
        for numero, linha in enumerate(f, 1):
            linha = linha.strip()
            if not linha:
                continue
            try:
                r = json.loads(linha)
            except ValueError:
                # Uma linha quebrada não descarta o arquivo: a gravação pode
                # ter sido interrompida no meio de uma escrita, e tudo o que
                # veio antes continua válido.
                print("%s:%d: linha ilegível, ignorada" % (caminho, numero),
                      file=sys.stderr)
                continue
            tipo = r.get("type")
            if tipo == "start":
                cabecalho = r
            elif tipo == "data":
                pedacos.append((float(r["time"]), base64.b64decode(r["b64"])))
            elif tipo == "truncated":
                truncado = True
            elif tipo == "end":
                fim = r
    if cabecalho is None:
        raise SystemExit("%s: sem registro de início; não é uma captura"
                         % caminho)
    return cabecalho, pedacos, fim, truncado


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2

    arquivos = [a for a in argv[1:] if not a.startswith("--")]
    raw_dir = None
    if "--raw" in argv:
        i = argv.index("--raw")
        if i + 1 >= len(argv):
            raise SystemExit("--raw precisa de um diretório")
        raw_dir = argv[i + 1]
        arquivos = [a for a in arquivos if a != raw_dir]

    if len(arquivos) != 2:
        raise SystemExit("são dois arquivos de captura, um de cada lado")

    lados = [carregar(a) for a in arquivos]

    # Conferência que vale mais que um aviso: se os dois arquivos não são as
    # duas metades da MESMA sessão, o resultado seria uma conversa que nunca
    # existiu -- e pareceria plausível.
    a, b = lados[0][0], lados[1][0]
    if a.get("number") != b.get("pair_number") or \
            b.get("number") != a.get("pair_number"):
        raise SystemExit(
            "estes dois arquivos não são o mesmo par: %s<->%s e %s<->%s"
            % (a.get("number"), a.get("pair_number"),
               b.get("number"), b.get("pair_number")))

    for (cab, pedacos, fim, truncado), nome in zip(lados, arquivos):
        print("# %s" % os.path.basename(nome))
        print("#   %s (%s) -> %s   %d pedaços, %d bytes%s"
              % (cab.get("number"), cab.get("role"), cab.get("pair_number"),
                 len(pedacos), sum(len(p) for _, p in pedacos),
                 "  TRUNCADO" if truncado else ""))
        if fim is None:
            # Sem registro de fim, a gravação foi cortada -- processo morto,
            # disco cheio. Dizer isso importa: a sessão pode ter continuado.
            print("#   sem registro de fim: gravação interrompida")
    print()

    tudo = []
    for cab, pedacos, _, _ in lados:
        for hora, dados in pedacos:
            tudo.append((hora, cab.get("number"), cab.get("role"), dados))
    tudo.sort(key=lambda x: x[0])

    if not tudo:
        print("(nenhum byte gravado nas duas pontas)")
        return 0

    inicio = tudo[0][0]
    for hora, numero, papel, dados in tudo:
        print("%8.3fs  %s %-8s  %4d bytes  %s"
              % (hora - inicio, numero, papel, len(dados), dados.hex()))

    if raw_dir:
        os.makedirs(raw_dir, exist_ok=True)
        for cab, pedacos, _, _ in lados:
            saida = os.path.join(
                raw_dir, "%s-%s.bin" % (cab.get("number"), cab.get("role")))
            with open(saida, "wb") as f:
                for _, dados in pedacos:
                    f.write(dados)
            print("\n%s: %d bytes" % (saida, os.path.getsize(saida)),
                  file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
