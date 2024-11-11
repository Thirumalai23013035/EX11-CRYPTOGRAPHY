Experiment 11: ELLIPTIC CURVE CRYPTOGRAPHY(ECC)
Aim:
To implement elliptic curve cryptography (ECC) for secure key exchange between two users.

Algorithm:
step-1 : Define a structure Point to represent points on the elliptic curve with x and y coordinates.

step-2 : Implement the mod_inverse function to compute the modular inverse of a number using the Extended Euclidean Algorithm.

step-3 : Define the add_points function to perform point addition on the elliptic curve.

step-4 : Define the scalar_multiplication function to perform scalar multiplication (point multiplication) by using the double-and-add method.

step-5 : Prompt the user to input the prime number p, curve parameters a and b, base point G, Alice's private key, and Bob's private key.

step-6 : Compute Alice's public key by performing scalar multiplication of the base point G with Alice's private key.

step-7 : Compute Bob's public key by performing scalar multiplication of the base point G with Bob's private key.

step-8 : Compute the shared secret for Alice by performing scalar multiplication of Bob's public key with Alice's private key.

step-9 : Compute the shared secret for Bob by performing scalar multiplication of Alice's public key with Bob's private key.

step-10 : Display the public keys and the shared secrets computed by both Alice and Bob.

step-11 : Verify if the shared secrets match and display whether the key exchange was successful.
```

NAME:THIRUMALAI V
Register no : 212223040229
```
#CODE:
#include <stdio.h>

// Define a structure to represent points on the elliptic curve
typedef struct {
    long long x, y;
} Point;

// Function to compute modular inverse (using Extended Euclidean Algorithm)
long long mod_inverse(long long a, long long p) {
    long long t = 0, new_t = 1;
    long long r = p, new_r = a;
    
    while (new_r != 0) {
        long long quotient = r / new_r;
        long long temp = t;
        t = new_t;
        new_t = temp - quotient * new_t;
        
        temp = r;
        r = new_r;
        new_r = temp - quotient * new_r;
    }
    
    if (r > 1) return -1;  // No inverse exists
    if (t < 0) t += p;
    
    return t;
}

// Function to perform point addition on elliptic curve
Point add_points(Point P, Point Q, long long a, long long p) {
    Point R;
    if (P.x == Q.x && P.y == Q.y) {
        // Case of P = Q (Point Doubling)
        long long m = (3 * P.x * P.x + a) * mod_inverse(2 * P.y, p) % p;
        R.x = (m * m - 2 * P.x) % p;
        R.y = (m * (P.x - R.x) - P.y) % p;
    } else {
        // Ordinary case
        long long m = (Q.y - P.y) * mod_inverse(Q.x - P.x, p) % p;
        R.x = (m * m - P.x - Q.x) % p;
        R.y = (m * (P.x - R.x) - P.y) % p;
    }

    // Ensure positive values
    if (R.x < 0) R.x += p;
    if (R.y < 0) R.y += p;

    return R;
}

// Function to perform scalar multiplication (Elliptic Curve Point Multiplication)
Point scalar_multiplication(Point P, long long k, long long a, long long p) {
    Point result = {0, 0}; // Point at infinity (neutral element)
    Point base = P;

    while (k > 0) {
        if (k % 2 == 1) {  // If k is odd, add base point
            result = add_points(result, base, a, p);
        }
        base = add_points(base, base, a, p);  // Double the point
        k /= 2;
    }
    return result;
}

int main() {
    long long p, a, b;
    Point G;
    long long alice_private_key, bob_private_key;
    Point alice_public_key, bob_public_key, alice_shared_secret, bob_shared_secret;

    // Input values
    printf("Enter the prime number (p): ");
    scanf("%lld", &p);
    printf("Enter the curve parameters (a and b) for equation y^2 = x^3 + ax + b: ");
    scanf("%lld %lld", &a, &b);
    printf("Enter the base point G (x and y): ");
    scanf("%lld %lld", &G.x, &G.y);
    printf("Enter Alice's private key: ");
    scanf("%lld", &alice_private_key);
    printf("Enter Bob's private key: ");
    scanf("%lld", &bob_private_key);

    // Compute public keys
    alice_public_key = scalar_multiplication(G, alice_private_key, a, p);
    bob_public_key = scalar_multiplication(G, bob_private_key, a, p);

    printf("Alice's public key: (%lld, %lld)\n", alice_public_key.x, alice_public_key.y);
    printf("Bob's public key: (%lld, %lld)\n", bob_public_key.x, bob_public_key.y);

    // Compute shared secrets
    alice_shared_secret = scalar_multiplication(bob_public_key, alice_private_key, a, p);
    bob_shared_secret = scalar_multiplication(alice_public_key, bob_private_key, a, p);

    printf("Shared secret computed by Alice: (%lld, %lld)\n", alice_shared_secret.x, alice_shared_secret.y);
    printf("Shared secret computed by Bob: (%lld, %lld)\n", bob_shared_secret.x, bob_shared_secret.y);

    // Verify if shared secrets match
    if (alice_shared_secret.x == bob_shared_secret.x && alice_shared_secret.y == bob_shared_secret.y) {
        printf("Key exchange successful. Shared secrets match.\n");
    } else {
        printf("Key exchange failed. Shared secrets do not match.\n");
    }

    return 0;
}
#Output:
![Screenshot 2024-11-11 082313](https://github.com/user-attachments/assets/d40ce109-cab6-4a56-8e63-0196736abfae)


#Result:
The program for Elliptic curve cryptography was written and executed successfully
