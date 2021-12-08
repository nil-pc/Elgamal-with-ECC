//Elgamal encryption with Elliptic curve
#include <stdio.h>
#include <iostream>
#include <cstring>
#include <math.h>

using namespace std;

//Coordinate system to define each point in a plane
typedef struct
{
	long int x,y;

}point;

//Values that define the elliptic curve
typedef struct 
{
	long int a, b, p;

}elliptic;

//Calculate m % p
long int calcMod(long int m, long int p)
{
	if (m >= 0)
	{
		m = m % p;
	}
	else
	{
		while (m < 0)
		{
			m = m + p;
		}
	}

	return m;
}

//Find inverse of a w.r.t b
long int getInverse(long int a, long int b)
{
	long int t, t1, t2, q, r, p;
	t1 = 0;
	t2 = 1;
	p = b;
	if(b == 1)
		return 0;
	while(b != 1)
	{
		q = b/a;
		r = b % a;
		t = t1 - (q*t2);
		b = a;
		a = r;
		t1 = t2;
		t2 = t; 
	}
	if(t1 < 0)
	{
        t1 += p;
	}
	return t1;

}

//Generate the base point
point generateBasePoint(elliptic ecc)
{
	long int x = 0, y = 0;
	long int lhs, rhs, m = 0;

	point G = { 0 , 0 };

	long int count = 0;

	while (count < (ecc.p * ecc.p))
	{
		if (m == 0 || m == 2)
		{
			x = (x + 1) % ecc.p;
		}
		if (m == 1)
		{
			x = (x - 1) % ecc.p;
			y = (y + 1) % ecc.p;
		}
		lhs = (y * y) % ecc.p;
		rhs = pow(x, 3) + (ecc.a * x) + ecc.b;
		rhs = rhs % ecc.p;
		if (lhs == rhs)
		{
			G.x = x;
			G.y = y;
			break;
		}
		m++;
		if (x == y)
		{
			m = 0;
		}
		count++;
	}
	return G;
}

//Add 2 points
point scalarMult(point p, point q, elliptic ecc)
{
	long int slope;
	long int den, den_inv;
	point sum;
	if((p.x == q.x) && (p.y == q.y))
	{
		den = 2 * p.y;
		den_inv = getInverse(den, ecc.p);
		slope = (((3*pow(p.x, 2)) + ecc.a) * den_inv);
		slope = calcMod(slope, ecc.p);
	}
	else
	{
		den = q.x - p.x;
		den = calcMod(den, ecc.p);
		den_inv = getInverse(den, ecc.p);
		slope = calcMod(((q.y - p.y) * den_inv), ecc.p);
	}

	sum.x = calcMod((pow(slope, 2) - p.x - q.x), ecc.p);
	sum.y = calcMod(((slope * (p.x - sum.x)) - p.y), ecc.p);

	return sum;	
}

//Find the order of base point
long int findOrder(elliptic ecc, point G)
{
	long int order = 2;
	point gen = { G.x, G.y };
	long int slope;
	long int den, den_inv;

	while(!((G.x == gen.x) && (G.y == ( ecc.p - gen.y))))
	{
        gen = scalarMult(G, gen, ecc);
		order ++;
	}
	return order - 1;
}

//Insert and store Private Key
long int genPrivKey()
{
	long int key;
	cout<<"\nEnter the private key for public key generation : \n";
	cin>>key;
	return key;
}

//Generate Public Key from Private Key
point genPubKey(point g, long int n, elliptic ecc)
{
	point pub = {g.x, g.y};
	long int i;
	for(i = 2; i <= n; ++i)
	{
		pub = scalarMult(g, pub, ecc);
	}
	return pub;
}

//Insert the random ephimeral key
long int genEphKey()
{
	long int k;
	cout<<"\nEnter an Ephimeral Key : \n";
	cin>>k;
	return k;
}

//Encryption function : C1 = kG C2 = P + kPubKey 
void ecc_enc(long int k, point g, point msg, point pA, point* c1, point* c2, elliptic ecc)
{
	long int i;
	point c = {g.x, g.y};
	for(i = 2; i<=k; i++)
	{
		c = scalarMult(g, c, ecc);
	}
	c1->x = c.x;
	c1->y = c.y;
	c = {pA.x, pA.y};
	for(i=2; i<= k; i++)
	{
		c = scalarMult(pA, c, ecc);
	}
	c = scalarMult(msg, c, ecc);
	c2->x = c.x;
	c2->y = c.y;
}

//Decryption function : P = C2 - (PrivKey * C1)
point ecc_dec(long int n, point c1, point c2, elliptic ecc)
{
	point c = { c1.x, c1.y};
	point dec_msg;
	long int i;
	for(i = 2; i<=n; i++)
	{
		c = scalarMult(c1, c, ecc);
	}
	c.y = -c.y;
    	dec_msg = scalarMult(c2, c, ecc);
    	return dec_msg;
}

int main()
{
	elliptic ecc;   
	point g, c1, c2, msg, dec_msg, pA;
	long int n, nA, k;
	cout<<"\nElliptic curve : (y^2)mod p = (x^3 + ax + b) mod p";
	cout<<"\nEnter values for a, b and p : \n";
	cin>>ecc.a>>ecc.b>>ecc.p;

	g = generateBasePoint(ecc);
	n = findOrder(ecc, g);
	cout<<"\nBase Point : ("<<g.x<<","<<g.y<<")";
	cout<<"\nOrder : "<<n;

	nA = genPrivKey();
	pA = genPubKey(g, nA, ecc);
	cout<<"\nPublic Key : ("<<pA.x<<","<<pA.y<<")";
	k  = genEphKey();

	cout<<"\nEnter msg for encryption x and y values : \n";
	cin>>msg.x>>msg.y;

	ecc_enc(k, g, msg, pA, &c1, &c2, ecc);
	cout<<"\nEncrypted msg : {("<<c1.x<<","<<c1.y<<") , ("<<c2.x<<","<<c2.y<<")}";

	cout<<"\nDecryption : ";
	dec_msg = ecc_dec(nA, c1, c2, ecc);

	cout<<"\nDecrypted msg : ("<<dec_msg.x<<","<<dec_msg.y<<")\n";

	return 0;
}
