from .ecdsa_pure import KEY
import argparse
import pickle as cPickle

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('players', help='The number of players')
    parser.add_argument('fname', help='fname')
    args = parser.parse_args()
    players = int(args.players)
    fname = args.fname
    keylist = []
    for i in range(players):
        key = KEY()
        key.generate()
        keylist.append(key.get_secret())
    #print(cPickle.dumps(keylist))
    with open(fname, "wb") as f:
        cPickle.dump(keylist, f)

if __name__ == '__main__':
    main()
