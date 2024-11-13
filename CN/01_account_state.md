# Account and Contract：계정 및 계약

## 개요

"이더리움과 비트코인의 가장 큰 차이점 중 하나는 서로 다른 온체인 데이터 모델을 사용한다는 점입니다.비트코인은 UTXO 모델을 기반으로 하는 블록체인/원장 시스템인 반면, 이더리움은 계정/스테이트 모델을 기반으로 합니다."라는 말을 자주 듣습니다.그렇다면 계정/스테이트 모델과 UTXO의 차이점은 무엇일까요?이번 아티클에서는 이더리움의 기본 데이터 구조 중 하나인 `Account`에 대해 살펴보겠습니다.

간단히 말해, 이더리움은 *거래 기반 상태 머신*(Transaction-based State Machine)으로 작동합니다.이 시스템은 은행 계좌와 유사한 여러 개의 계정으로 구성됩니다. 스테이트는 특정 시점의 계정 가치를 반영합니다. 이더리움에서는 스테이트에 해당하는 기본 데이터 구조를 스테이트 오브젝트라고 하며, 스테이트 오브젝트의 값이 변경될 때 이를 *스테이트 전송*이라고 합니다. 이더리움의 운영 모델에서 스테이트 오브젝트에 포함된 데이터는 트랜잭션의 결과로 업데이트/삭제/생성되며, 이는 스테이트 전송, 즉 현재 스테이트에서 다른 스테이트로 스테이트 오브젝트의 상태를 전송하는 것을 트리거합니다.

이더리움에서 스테이트 오브젝트를 호스팅하는 특정 인스턴스는 이더리움의 계정입니다.일반적으로 스테이트는 특정 시점에 계정에 포함된 데이터의 값을 가리킵니다.

- Account --> StateObject
- State   --> The value/data of the Account

일반적으로 계정은 체인에서 트랜잭션의 기본 역할이며, 이더리움 상태 머신 모델의 기본 단위로, 체인에서 트랜잭션의 개시자와 수신자 역할을 모두 맡습니다.현재 이더리움에는 두 가지 유형의 계정, 즉 외부 계정(EOA)과 콘트랙트가 있습니다.

외부 계정(EOA)은 사용자가 직접 제어하며 거래(트랜잭션)의 서명 및 시작을 담당하는 계정입니다.사용자는 계정의 개인 키를 제어하여 계정 데이터에 대한 통제권을 확보합니다.

컨트랙트라고 하는 계약 계정(컨트랙트)은 트랜잭션을 통해 외부 계정에 의해 생성됩니다.컨트랙트 계정은 **변조 방지 튜링 완전 코드 세그먼트**와 일부 **영구 데이터 변수**를 보유합니다.이 코드는 특수한 튜링 완전 프로그래밍 언어(솔리디티)로 작성되며, 일반적으로 API 인터페이스 기능에 대한 일부 외부 액세스를 제공합니다.이러한 API 인터페이스 함수는 트랜잭션을 구성하거나 로컬/서드파티가 제공하는 노드 RPC 서비스를 통해 호출할 수 있습니다.이 모델은 현재 디앱 생태계의 근간을 이루고 있습니다.

일반적으로 콘트랙트의 함수는 콘트랙트의 영구 데이터를 계산하고 쿼리하거나 수정하는 데 사용됩니다."**블록체인에 한 번 기록된 데이터는 수정할 수 없다**" 또는 "**변조 방지 스마트 컨트랙트**"와 같은 설명을 종종 볼 수 있습니다.하지만 이러한 일반적인 설명은 사실 부정확하다는 것을 알고 있습니다.온체인 스마트 콘트랙트의 경우, 수정/변조가 불가능한 부분은 콘트랙트의 코드 세그먼트이거나, 콘트랙트의 *기능적 로직*/*코드 로직이 수정/변조가 *불가능*한 부분입니다.그리고 컨트랙트의 **영구 데이터 변수**는 코드 세그먼트에서 함수를 호출하여 데이터를 조작할 수 있습니다(CURD).정확한 조작은 컨트랙트 함수의 코드 로직에 따라 달라집니다.

根据*合约中函数是否会修改合约中持久化的变量*，合约中的函数可以分为两种: *只读函数*和*写函数*。如果用户**只**希望查询某些合约中的持久化数据，而不对数据进行修改的话，那么用户只需要调用相关的只读函数。调用只读函数不需要通过构造一个 Transaction 来查询数据。用户可以通过直接调用本地节点或者第三方节点提供的 RPC 接口来直接调用对应的合约中的*只读函数*。如果用户需要对合约中的数据进行更新，那么他就要构造一个 Transaction 来调用合约中相对应的*写函数*。注意，每个 Transaction 每次调用一个合约中的一个*写函数*。因为，如果想在链上实现复杂的逻辑，需要将*写函数*接口化，在其中调用更多的逻辑。
컨트랙트의 함수가 컨트랙트 내의 영구적인 변수를 수정하는지 여부에 따라, 컨트랙트의 함수는 두 가지로 분류될 수 있습니다: 읽기 전용 함수와 쓰기 함수입니다. 사용자가 오직 일부 컨트랙트의 영구 데이터를 조회하고 데이터를 수정하지 않으려는 경우, 관련된 읽기 전용 함수만 호출하면 됩니다. 읽기 전용 함수를 호출할 때는 데이터를 조회하기 위해 트랜잭션을 생성할 필요가 없습니다. 사용자는 로컬 노드나 제3자 노드에서 제공하는 RPC 인터페이스를 통해 해당 컨트랙트의 읽기 전용 함수를 직접 호출할 수 있습니다.

만약 사용자가 컨트랙트 내의 데이터를 업데이트해야 한다면, 해당 컨트랙트의 쓰기 함수를 호출하기 위해 트랜잭션을 생성해야 합니다. 주의할 점은, 각 트랜잭션은 한 번에 하나의 컨트랙트에서 하나의 쓰기 함수만 호출한다는 것입니다. 이는 온체인에서 복잡한 로직을 구현하려면 쓰기 함수를 인터페이스화하여 그 안에서 더 많은 로직을 호출해야 하기 때문입니다.

컨트랙트을 어떻게 작성하는지, 그리고 Ethereum의 실행 레이어가 트랜잭션을 어떻게 해석하고 해당 컨트랙트의 함수를 호출하는지에 대해서는 이후의 글에서 자세히 분석하겠습니다.

## StateObject, Account, Contract：状态、账户、合约

### 概述

실제 코드에서 이 두 종류의 Account는 `stateObject`라는 데이터 구조에 의해 정의됩니다. `stateObject`의 관련 코드는 core/state/state_object.go 파일에 위치하며, package state에 속해 있습니다. 우리는 `stateObject`의 구조 코드를 아래와 같이 발췌했습니다. 아래의 코드를 통해 `stateObject`가 소문자로 시작한다는 것을 관찰할 수 있습니다. Go 언어의 특성상, 이 구조체는 주로 패키지 내부의 데이터 조작에 사용되며 외부에는 공개되지 않습니다.

```go
  type stateObject struct {
    address  common.Address
    addrHash common.Hash // hash of ethereum address of the account
    data     types.StateAccount
    db       *StateDB
    dbErr error

    // Write caches.
    trie Trie // storage trie, which becomes non-nil on first access
    code Code // contract bytecode, which gets set when code is loaded

    // 여기 저장소는 map[common.Hash]common.Hash입니다.
    originStorage  Storage // Storage cache of original entries to dedup rewrites, reset for every transaction
    pendingStorage Storage // Storage entries that need to be flushed to disk, at the end of an entire block
    dirtyStorage   Storage // Storage entries that have been modified in the current transaction execution
    fakeStorage    Storage // Fake storage which constructed by caller for debugging purpose.

    // Cache flags.
    // When an object is marked suicided it will be delete from the trie
    // during the "update" phase of the state transition.
    dirtyCode bool // true if the code was updated
    suicided  bool
    deleted   bool
  }
```

### Address：地址

`stateObject` 구조체에서, 처음 두 개의 멤버 변수는 address와 주소의 해시 값인 addrHash입니다. address는 common.Address 타입이고, addrHash는 common.Hash 타입입니다. 이들은 각각 20바이트 길이의 바이트 배열과 32바이트 길이의 바이트 배열에 해당합니다. 이 두 가지 데이터 타입의 정의는 다음과 같습니다.

```go
// Lengths of hashes and addresses in bytes.
const (
 // HashLength is the expected length of the hash
 HashLength = 32
 // AddressLength is the expected length of the address
 AddressLength = 20
)
// Address represents the 20 byte address of an Ethereum account.
type Address [AddressLength]byte
// Hash represents the 32 byte Keccak256 hash of arbitrary data.
type Hash [HashLength]byte
```

이더리움에서 각 Account는 고유한 주소(Address)를 가지고 있습니다. Address는 각 Account의 신원 정보로서 현실 생활의 신분증과 유사하며, 사용자 정보와 항상 연결되어 변경할 수 없습니다.

### data and StateAccount：数据与状态账户

계속해서 탐색해보면, 우리는 멤버 변수 `data`를 만나게 되는데, 이는 `types.StateAccount` 타입의 변수입니다. 앞서의 분석에서 우리는 `stateObject` 타입이 Package State 내부에서만 사용된다고 언급했습니다. 이에 따라 Package State는 외부 패키지 API에 Account와 관련된 데이터 타입인 `State Account`를 제공합니다. 위의 코드에서 우리는 `State Accoun`t가 `State Object`의 `data Account` 멤버 변수에 대응한다는 것을 볼 수 있습니다. State Account의 구체적인 데이터 구조는 c`ore/types/state_account.go` 파일에 정의되어 있습니다(~~이전 버전에서는 Account의 코드가 core/account.go에 위치했습니다~~). 그 정의는 다음과 같습니다.

```go
// Account is the Ethereum consensus representation of accounts.
// These objects are stored in the main account trie.
type StateAccount struct {
  Nonce    uint64
  Balance  *big.Int
  Root     common.Hash // merkle root of the storage trie
  CodeHash []byte
}
```

그 안에는 네 개의 변수가 포함되어 있습니다:

- Nonce는 해당 계정이 보낸 거래의 시퀀스 번호를 나타내며, 계정이 보낸 거래 수의 증가에 따라 단조롭게 증가합니다. 거래를 한 번 보낼 때마다 Nonce의 값은 1씩 증가합니다.
- Balance는 해당 계정의 잔액을 나타냅니다. 여기서 잔액은 체인상의 네이티브 토큰인 이더(Ether)를 의미합니다.
- Root는 현재 계정의 하위 스토리지 계층에 있는 머클 패트리샤 트리(Merkle Patricia Trie)의 루트를 나타냅니다. 이 스토리지 계층은 계약의 영구적인 변수를 관리하기 위해 준비된 것입니다. EOA 계정의 경우 이 부분은 빈 값(null)입니다.
- CodeHash는 해당 계정의 계약 코드의 해시 값입니다. 마찬가지로, 이 변수는 계약 계정의 코드의 해시를 저장하는 데 사용되며, EOA 계정의 경우 이 부분은 빈 값(null)입니다.

### db：포괄적인 데이터베이스

위에서 언급한 몇 가지 멤버 변수들은 기본적으로 Account 주요 라이프사이클과 관련된 모든 멤버 변수를 포함합니다. 그러면 계속해서 아래로 내려가면 `db`와 `dbErr` 이 두 멤버 변수를 만나게 됩니다. `db` 변수는 `StateDB` 타입의 포인터를 저장하고 있습니다. 이는 Account에 대응하는 `stateObject`를 조작하기 위해 StateDB 관련 API를 호출하기 편리하게 하기 위한 것입니다. 본질적으로 StateDB는 stateObject 정보를 관리하기 위해 추상화된 인메모리 데이터베이스입니다. 모든 Account 데이터의 업데이트와 조회는 StateDB에서 제공하는 API를 사용하게 됩니다. StateDB의 구체적인 구현, 기능, 그리고 더 하위의 물리적 스토리지 계층(leveldb)과 어떻게 결합하는지에 대해서는 이후의 글에서 자세히 설명하겠습니다.

### Cache：캐시

남아있는 멤버 변수들은 주로 메모리 캐싱에 사용됩니다. trie는 계약 계정의 영구적인 변수 저장 데이터를 저장하고 관리하는 데 사용됩니다. code는 계약의 코드 섹션을 메모리에 캐시하는 데 사용되며, 이는 byte 타입의 배열입니다. 남은 네 개의 Storage 필드는 주로 트랜잭션을 실행할 때 계약이 수정한 영구적인 데이터를 캐시하는 데 사용됩니다. 예를 들어, dirtyStorage는 블록이 최종 확정되기 전에 트랜잭션이 수정한 계약의 영구 저장 데이터를 캐시하는 데 사용됩니다. 외부 계정의 경우 코드 필드가 없기 때문에, 해당하는 stateObject 객체의 code 필드와 네 개의 Storage 타입 필드에 대응하는 변수들의 값은 모두 비어 있습니다(originStorage, pendingStorage, dirtyStorage, fakeStorage).

호출 관계 측면에서 보면, 이 네 개의 캐시 변수의 수정 순서는 다음과 같습니다: originStorage --> dirtyStorage --> pendingStorage. 계약의 Storage 계층에 대한 자세한 정보는 이후 부분에서 상세히 설명하겠습니다.

## 심화 Account (EOA)

### 누가 당신의 계정을 지배하는가

우리는 다양한 기술 웹사이트나 미디어에서 다음과 같은 말을 자주 접합니다. "사용자가 블록체인 시스템에 보관한 암호화폐/토큰은 사용자 자신을 제외하고는, 사용자의 허락 없이 제3자가 당신의 자산을 옮길 수 없다." 이 말은 기본적으로 맞습니다. 현재, 사용자 계정에 있는 체인 레벨에서 정의된 암호화폐/토큰, 즉 네이티브 토큰(Native Token)이라고 불리는 것들, 예를 들어 이더(Ether), 비트코인(Bitcoin), BNB(바이낸스 스마트 체인에서만 사용 가능)는 사용자의 승인 없이 제3자가 옮길 수 없습니다. 이는 체인 레벨의 모든 데이터 변경은 사용자의 개인 키(Private Key)로 서명된 트랜잭션을 실행해야 하기 때문입니다. 따라서 사용자가 자신의 계정의 개인 키를 잘 보관하고, 제3자가 알지 못하도록 한다면, 아무도 당신의 체인 상의 자산을 옮길 수 없습니다.


우리는 위의 말이 기본적으로 맞지만, 완전히 정확하지는 않다고 말했습니다. 그 이유는 두 가지입니다.

첫째, 사용자의 온체인 데이터 보안은 현재 `Go-ethereum`에서 사용하는 암호학 도구가 충분히 보장된다는 것에 기반합니다. 즉, 사용자의 프라이빗 키를 알지 못하는 전제 하에서, 제3자가 유한한 시간 내에 사용자의 프라이빗 키 정보를 얻어 서명된 트랜잭션을 위조할 수 없다는 것입니다. 이 보안 보장의 전제는 현재 이더리움에서 사용하는 암호학 도구의 강도가 충분히 커서, 어떤 컴퓨터도 유한한 시간 내에 사용자의 프라이빗 키를 해킹할 수 없다는 것입니다. 양자 컴퓨터가 등장하기 전까지, 현재 이더리움과 다른 블록체인에서 사용하는 암호학 도구의 강도는 모두 충분히 안전합니다. 이것이 많은 새로운 블록체인 프로젝트가 양자 컴퓨터에 대응하는 암호 체계를 연구하는 이유이기도 합니다.

둘째, 현재 많은 이른바 암호화폐/토큰이 체인 레벨의 토큰이 아니라 계약의 영구 변수에 저장된 데이터입니다. 예를 들어 ERC-20 토큰과 NFT에 해당하는 ERC-721 토큰이 그렇습니다. 이러한 토큰들은 모두 계약 코드 기반으로 생성되고 유지되기 때문에, 이 토큰들의 안전성은 계약 자체의 안전성에 의존합니다. 만약 계약 코드에 문제가 있어 백도어나 취약점이 존재한다면, 예를 들어 제3자가 다른 계정의 토큰을 임의로 추출할 수 있는 취약점이 있다면, 사용자의 프라이빗 키 정보가 유출되지 않았더라도 계약 내의 토큰은 여전히 제3자에게 탈취될 수 있습니다. 계약의 코드 섹션은 체인상에서 수정할 수 없기 때문에, 계약 코드의 안전성은 매우 중요합니다. 현재 많은 연구자들과 기술 팀들이 계약 감사를 진행하여 업로드된 계약 코드의 안전성을 보장하고 있습니다.

레이어 2 기술과 일부 크로스체인 기술의 발전에 따라, 사용자가 보유한 `토큰`은 많은 경우 우리가 앞서 언급한 프라이빗 키로 안전이 보장되는 네이티브 토큰이 아니라 ERC-20 토큰입니다. 이러한 토큰은 계약 내의 간단한 수치 기록에 불과합니다. 이러한 유형의 자산의 안전성은 레이어 1 상의 네이티브 토큰보다 훨씬 낮습니다. 사용자는 이러한 자산을 보유할 때 주의해야 합니다. 여기에서 우리는 Jay Freeman이 분석한 인기 있는 레이어 2 시스템인 Optimism에서 네이티브 토큰이 아닌 것으로 인해 발생한 임의 추출 취약점을 읽어볼 것을 권장합니다. (https://www.saurik.com/optimism.html)

### Account Generation：계정 생성

먼저, EOA 계정의 생성은 로컬 생성과 온체인 등록 두 부분으로 나뉩니다. 우리가 Metamask와 같은 지갑 도구를 사용하여 계정을 생성할 때, 블록체인에 계정 정보가 동기화되어 등록되는 것은 아닙니다. 온체인 계정의 생성과 관리는 모두 `StateDB` 모듈을 통해 이루어지므로, 우리는 `geth`의 계정 관리 부분 코드를 `StateDB` 모듈 챕터에 통합하여 함께 설명하겠습니다. 그리고 계약 계정, 즉 스마트 컨트랙트의 생성은 EOA 계정을 통해 특정한 트랜잭션을 구성하여 생성해야 합니다. 이 부분의 세부 사항에 대해서도 이후의 챕터에서 분석하도록 하겠습니다.

이제 로컬에서 EOA 계정을 어떻게 생성하는지 간단히 분석해보겠습니다.

일반적으로, 새로운 계정을 생성하는 데 의존하는 진입 함수 `NewAccount`는 `accounts/keystore/keystore.go` 파일에 위치해 있습니다. 이 함수는 문자열 타입의 passphrase 파라미터를 가지고 있습니다. 주의할 점은, 이 파라미터는 로컬에 저장된 프라이빗 키의 키스토어 파일을 암호화하는 데만 사용되며, 계정의 프라이빗 키와 주소의 생성과는 무관하다는 것입니다.

```go
// passphrase 매개변수는 로컬 암호화에 사용됨
func (ks *KeyStore) NewAccount(passphrase string) (accounts.Account, error) {
//계정을 생성하는 함수
 _, account, err := storeNewKey(ks.storage, crand.Reader, passphrase)
 if err != nil {
  return accounts.Account{}, err
 }
 // Add the account to the cache immediately rather
 // than waiting for file system notifications to pick it up.
 ks.cache.add(account)
 ks.refreshWallets()
 return account, nil
}
```

위의 코드 단락에서 가장 핵심적인 호출은 `storeNewKey` 함수입니다. `storeNewKey` 함수에서는 먼저 `newKey` 함수를 호출하는데, 이 함수의 주요 기능은 계정에 필요한 비밀키와 공개키 쌍을 생성하는 것입니다. 그리고 `newKey` 함수의 핵심은 타원 곡선 암호화 쌍을 생성하는 관련 함수인 `ecdsa.GenerateKey`를 호출하는 것입니다.

```go
func newKey(rand io.Reader) (*Key, error) {
 privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)
 if err != nil {
  return nil, err
 }
 return newKeyFromECDSA(privateKeyECDSA), nil
}

```

이 부분의 코드는 `crypto/ecdsa.go` 파일에 위치해 있습니다. 이 부분은 타원 곡선 암호화에 대한 많은 지식을 포함하고 있으며, 이더리움의 주요 비즈니스와 큰 관련이 없기 때문에, 여기서는 주요 흐름만 간단히 설명하겠습니다. 암호학 원리에 대한 자세한 내용은 여기서 다루지 않으며, 관심 있는 독자께서는 직접 찾아보시기 바랍니다. 주목할 것은, 전체 과정에서 먼저 생성되는 것은 계정의 프라이빗 키이며, 계정에 대응하는 주소는 해당 프라이빗 키를 기반으로 타원 곡선에서 얻은 퍼블릭 키 값을 해시 계산하여 얻어진다는 점입니다.

다음은 계정 프라이빗 키로부터 계정 주소를 계산하는 방법을 간단히 설명하겠습니다.

- 첫째, 새로운 EOA 계정을 생성할 때 `GenerateKey` 함수를 통해 무작위로 프라이빗 키 한 줄을 얻습니다. 이는 32바이트 길이의 변수로, 64자리 16진수로 표현됩니다. 이 프라이빗 키는 사용자가 지갑을 활성화하거나 거래를 보낼 때 필요한 필수적인 열쇠이며, 이 프라이빗 키가 노출되면 지갑은 더 이상 안전하지 않습니다.
  - 64자리 16진수, 256비트, 32바이트
    `var AlicePrivateKey = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"`
- 둘째, 프라이빗 키를 얻은 후, 이를 사용하여 퍼블릭 키와 주소를 계산합니다. 앞서의 프라이빗 키를 기반으로, ECDSA 알고리즘에서 secp256k1 곡선을 선택하여 계산합니다. 선택한 타원 곡선에 프라이빗 키를 대입하여 점의 좌표를 계산하면 퍼블릭 키가 됩니다. 이더리움과 비트코인은 동일한 secp256k1 곡선을 사용하며, 실제 코드에서 go-Ethereum이 비트코인의 secp256k1 C 언어 코드를 직접 호출하는 것을 볼 수 있습니다.
    `ecdsaSK, err := crypto.ToECDSA(privateKey)`
- 셋째, 프라이빗 키를 타원 곡선 암호화를 수행한 후, 64바이트의 숫자를 얻을 수 있으며, 이는 두 개의 32바이트 숫자로 구성됩니다. 이 두 숫자는 secp256k1 곡선 상의 한 점의 X, Y 좌표를 나타냅니다.
    `ecdsaPK := ecdsaSK.PublicKey`
- 마지막으로, 계정 주소는 앞서의 퍼블릭 키(ecdsaSK.PublicKey)를 기반으로 ``Keccak-256` 알고리즘을 사용하여 해시 계산을 한 후, 그 결과의 마지막 20바이트를 취하고, 0x를 앞에 붙여 표시합니다(Keccak-256은 SHA-3(Secure Hash Algorithm 3) 표준의 하나인 해시 알고리즘입니다).
    `addr := crypto.PubkeyToAddress(ecdsaSK.PublicKey)`

#### Signature & Verification：서명과 검증

여기에서 우리는 ECDSA를 이용하여 디지털 서명과 검증을 어떻게 수행하는지 간단히 설명하겠습니다.

- Hash（m,R）*X +R = S* P
- P는 타원 곡선 함수의 기준점(base point)입니다. 이는 곡선 C 위에서 차수가 n인 덧셈 순환군의 생성원으로 이해할 수 있으며, n은 큰 소수입니다.
- R = r * P (r 是个随机数，并不告知verifier)
- 이더리움 서명 검증의 핵심 아이디어는 먼저 위에서 얻은 ECDSA의 개인 키 ecdsaSK로 데이터 msg를 서명하여 msgSig를 얻는 것입니다.
    `sig, err := crypto.Sign(msg[:], ecdsaSK)`
    `msgSig := decodeHex(hex.EncodeToString(sig))`
- 그런 다음 msg와 msgSig를 기반으로 서명에 사용된 공개 키(계정 주소를 생성하는 데 사용되는 공개 키 ecdsaPK)를 역으로 추출할 수 있습니다.
    `recoveredPub, err := crypto.Ecrecover(msg[:],msgSig)`
- 역으로 추출한 공개 키를 통해 발신자의 주소를 얻을 수 있으며, 현재 거래의 발신자의 ECDSA 공개 키와 비교할 수 있습니다.
    `crypto.VerifySignature(testPk, msg[:], msgSig[:len(msgSig)-1])`
- 이 시스템의 보안은 공개 키 ecdsaPK 또는 ecdsaSK.PublicKey를 알고 있더라도 ecdsaSK 및 그것을 생성한 privateKey를 추측하기 어렵다는 데 기반합니다.

#### ECDSA & spec256k1：연산에 사용되는 곡선

마지막으로, ECDSA의 원리를 간단히 설명하겠습니다. 관심 있는 독자께서는 이를 출발점으로 삼아 직접 찾아보실 수 있습니다.

- spec256k1 해석 함수는 y^2 = x^3 +7 입니다.
- 타원 곡선 상에는 타원 곡선 점 곱셈(Elliptic curve point multiplication)이라고 불리는 특별한 계산이 있으며, 그 계산 규칙은 다음과 같습니다:
  - Point addition P + Q = R
  - Point doubling P + P = 2P
- ECC에서의 '+' 기호는 일반적인 사칙연산의 덧셈이 아니라, 타원 곡선 C 위에서 정의된 새로운 이항 연산(점 곱셈)입니다. 이는 두 점 P와 Q를 지나는 직선이 타원 곡선 C와 만나는 또 다른 점 𝑅′의 X축 대칭인 점 R을 나타냅니다. C는 X축에 대하여 대칭이므로, X축 대칭의 점들도 모두 타원 곡선 위에 있습니다.
- 기준점 P는 타원 곡선 위에서 군의 생성원입니다.
- 기준점 P에 x번의 연산을 수행하여 점 X를 얻으며, 여기서 x는 프라이빗 키, X는 퍼블릭 키입니다. x는 계정의 프라이빗 키로부터 얻어집니다.

## Contract：계약과 계약 저장소

- 이 부분의 예제 코드는 다음 위치에 있습니다: [[example/signature](example/signature)]中。

### Contract Storage：계약 저장소

<!-- TODO: 이 부분은 미래에 EVM 챕터로 통합될 것입니다. -->

[글의 서두에서](#general Background) 우리는 외부 계정에 대응하는 `stateObject` 구조체의 인스턴스에서 네 개의 `Storage` 타입 변수가 빈 값(null)이라고 언급했습니다. 이는 분명히 이 네 개의 변수는 `Contract` 타입의 계정을 위해 준비된 것입니다.

`state_object.go` 파일의 처음 부분(약 41행)에 `Storage` 타입의 정의를 찾을 수 있습니다. 구체적인 내용은 다음과 같습니다. 

```go
type Storage map[common.Hash]common.Hash
```

我们可以看到，`Storage` 是一个 key 和 value 都是 `common.Hash` 类型的 map 结构。`common.Hash` 类型本质上是一个长度为 32bytes 的 `byte` 类型数组。`common.Hash` 类型在 `go-ethereum` 的代码库中被大量使用，通常用于表示32字节长度的数据，比如 `Keccak256` 函数的哈希值。在之后的旅程中，我们也会经常看到它的身影，它的定义在 `common.type.go` 文件中。

```go
// HashLength is the expected length of the hash
HashLength = 32
// Hash represents the 32 byte Keccak256 hash of arbitrary data.
type Hash [HashLength]byte
```

우리는 Storage가 key와 value 모두 `common.Hash` 타입인 map 구조라는 것을 볼 수 있습니다. `common.Hash` 타입은 본질적으로 길이가 32바이트인 byte 타입 배열입니다. `common.Hash` 타입은 `go-ethereum` 코드베이스에서 많이 사용되며, 일반적으로 `Keccak256` 함수의 해시 값과 같이 32바이트 길이의 데이터를 나타냅니다. 이후 여정에서도 자주 등장할 것이며, 그 정의는 `common.type.go` 파일에 있습니다.

데이터 측면에서, 외부 계정(EOA)과 계약 계정(Contract)의 차이점은 외부 계정은 자신의 코드(codeHash)와 추가적인 Storage 계층을 유지하지 않는다는 것입니다. 외부 계정에 비해 계약 계정은 추가적으로 Storage 계층을 저장하여 계약 코드에서 영구적인 변수를 저장하는 데 사용합니다. 앞서 우리는 StateObject 구조체에 선언된 네 개의 Storage 타입 변수가 계약의 Storage 계층의 메모리 캐시로 사용된다고 언급했습니다.

이더리움에서 각 계약은 자신의 독립적인 저장 공간을 유지하여 계약의 영구적인 변수를 저장하는 데 사용하며, 이를 Storage 계층이라고 부릅니다. Storage 계층의 기본 구성 단위는 슬롯(Slot)이라고 합니다. 여러 개의 Slot이 스택(Stack) 방식으로 순서대로 모여 Storage 계층을 구성합니다. 각 Slot의 크기는 256비트이며, 최대 32바이트의 데이터를 저장할 수 있습니다. 기본적인 저장 단위로서 Slot의 관리 방식은 메모리나 HDD의 기본 단위 관리 방식과 유사하며, 주소 인덱싱 방식을 통해 상위 함수에서 접근됩니다. Slot의 주소 인덱스 길이도 32바이트(256비트)이며, 주소 공간은 0x0000000000000000000000000000000000000000000000000000000000000000부터 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF까지입니다. 따라서 각 계약의 Storage 계층은 최대 2^256−1개의 Slot을 저장할 수 있습니다. 이는 이론적으로 하나의 계약이 최대 (2^256−1)개의 32바이트 데이터를 저장할 수 있다는 의미로, 상당히 큰 숫자입니다.

Storage 계층의 Slot 데이터를 더 잘 관리하기 위해 계약은 마찬가지로 MPT(Merkle Patricia Trie)를 인덱스로 사용하여 Storage 계층의 Slot을 관리합니다. 여기서 주목할 점은, 계약 Storage 계층의 데이터는 트랜잭션과 함께 블록에 포함되어 패키징되지 않는다는 것입니다. 앞서 언급했듯이, 계약 계정의 Storage Trie의 루트 데이터 관리는 StateAccount 구조체의 Root 변수에 저장됩니다(이는 32바이트 길이의 바이트 배열입니다). 특정 계약의 Storage 계층 데이터가 변경되면 상위로 전달되어 World State Root의 값이 업데이트되어 체인 데이터에 영향을 미칩니다. 현재 Storage 계층의 데이터 읽기 및 수정은 관련 트랜잭션을 실행할 때 EVM에서 두 개의 전용 지시어인 OpSload와 OpSstore를 호출하여 수행됩니다. 이 두 지시어의 구체적인 구현 원리에 대해서는 이후 EVM 챕터에서 자세히 해석하겠습니다.

우리는 현재 이더리움의 대부분의 계약이 Solidity 언어로 작성된다는 것을 알고 있습니다. Solidity는 강타입의 튜링 완전 언어로, 다양한 타입의 변수를 지원합니다. 일반적으로, 변수의 길이 특성에 따라 이더리움의 영구적인 변수는 고정 길이 변수와 가변 길이 변수 두 가지로 나눌 수 있습니다. 고정 길이 변수에는 흔한 단일 변수 타입인 uint256 등이 있습니다. 가변 길이 변수에는 여러 단일 변수로 구성된 배열(Array)과 키-값 형태의 맵(Map) 타입이 포함됩니다.

위의 소개를 통해, 우리는 계약 Storage 계층에 대한 접근이 Slot의 주소를 통해 이루어진다는 것을 알았습니다. 독자들께서는 다음의 몇 가지 질문에 대해 먼저 생각해 보시기 바랍니다:

- **다수의 퍼시스턴트 스토리지 변수를 포함하는 솔리디티에 대한 컨트랙트가 주어졌을 때, EVM은 어떻게 포함된 변수에 대한 스토리지 공간을 할당하나요?**
- 컨트랙트 스토리지의 일관된 읽기 및 쓰기를 어떻게 보장하나요?(각 컨트랙트의 유효성 검사기와 실행자가 동일한 데이터를 얻도록 어떻게 보장하나요?)

아래 몇 가지 예를 통해 이더리움의 컨트랙트가 어떻게 영구 변수를 유지하고 모든 참여자가 컨트랙트의 데이터를 일관되게 읽고 쓸 수 있는지 보여드리겠습니다.

### 계약 스토리지 사례 1：Storing Numbers

컨트랙트 스토리지 레이어의 로직을 보여주기 위해 간단한 컨트랙트를 사용하며, 컨트랙트 코드는 아래와 같습니다.이 예시에서는 Storage라는 컨트랙트를 사용하여 number, number1, number2 유형의 세 가지 영구 uint256 변수를 정의하고, 이 세 가지 변수에 값을 할당하는 store 함수를 정의합니다.컨트랙트 코드는 아래와 같습니다.

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

/**
 * @title Storage
 * @dev Store & retrieve value in a variable
 */
contract Storage {

    uint256 number;
    uint256 number1;
    uint256 number2;

    function stores(uint256 num) public {
        number = num;
        number1 = num + 1;
        number2 = num + 2;
    }
    
    function get_number() public view returns (uint256){
        return number;
    }
    
    function get_number1() public view returns (uint256){
        return number1;
    }
    
    function get_number2() public view returns (uint256){
        return number2;
    }
}
```

우리는 Remix(https://remix.ethereum.org/)를 사용하여 이 계약을 로컬에 배포하고, `stores(1)` 함수를 호출하는 트랜잭션을 구성한 다음, Remix 디버거를 사용하여 Storage 계층의 변화를 관찰합니다. 트랜잭션이 실행된 후, 계약의 세 개 변수의 값은 각각 1, 2, 3으로 할당됩니다. 이때 Storage 계층을 관찰하면 세 개의 Storage Object가 추가된 것을 발견할 수 있습니다. 이 세 개의 Storage Object는 세 개의 Slot에 대응합니다. 따라서 이 예제에서 계약은 데이터를 저장하기 위해 세 개의 Slot을 추가로 사용합니다. 우리는 각 Storage Object가 세 개의 필드로 구성되어 있음을 발견할 수 있습니다: 각각 32바이트의 key 필드와 32바이트의 value 필드, 그리고 외부의 32바이트 필드입니다. 이 세 개의 필드는 아래 예제에서 모두 64자리 16진수(32바이트)로 표현됩니다.

이제 이 세 값의 실제 의미를 하나씩 설명하겠습니다. 먼저 내부의 Key-Value 쌍을 관찰하면, 아래 세 개의 Storage Object에서 key의 값이 사실 0부터 시작하는 증가하는 정수임을 알 수 있습니다. 각각 0, 1, 2입니다. 이는 현재 Slot의 주소 인덱스 값을 나타내며, 즉 해당 Slot이 Storage 계층에서 대응하는 **절대 위치(Position)**를 의미합니다. 예를 들어, key의 값이 0이면 Storage 계층 전체에서 첫 번째 Slot을 나타내며, 즉 1번 위치의 Slot입니다. key가 1이면 Storage 계층의 두 번째 Slot을 나타내고, 이와 같이 계속됩니다. 각 Storage Object의 value 변수는 계약의 세 개 변수 값(1, 2, 3)을 저장합니다.

그리고 Storage Object의 외부 값은 Storage Object의 key 값의 sha3 해시 값과 동일합니다. 예를 들어, 아래 예제에서 첫 번째 Storage Object의 외부 인덱스 값 `0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563`는 `keccak256(0)`의 계산 결과와 같으며, 이는 첫 번째 Slot 위치의 Sha3 해시를 나타냅니다. 그리고 `0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6`는 `keccak(1)`의 계산 결과와 같습니다. 우리는 예제 코드에서 계산 과정을 보여주었습니다.

```json
{
 "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563": {
  "key": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "value": "0x0000000000000000000000000000000000000000000000000000000000000001"
 },
 "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6": {
  "key": "0x0000000000000000000000000000000000000000000000000000000000000001",
  "value": "0x0000000000000000000000000000000000000000000000000000000000000002"
 },
 "0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace": {
  "key": "0x0000000000000000000000000000000000000000000000000000000000000002",
  "value": "0x0000000000000000000000000000000000000000000000000000000000000003"
 }
}
```

여기까지 읽으셨다면, 이 Storage Object에서 외부의 인덱스 값과 Key 값의 관계가 일대일로 대응된다는 것을 이미 발견하셨을 것입니다. 다시 말해, 이 두 키 값은 본질적으로 Slot 위치에 대한 유일한 인덱스입니다. 여기서 이 두 값의 사용상의 차이점을 간단히 설명하겠습니다.

Key 값은 Storage 계층에서 Slot의 위치(Position)를 나타냅니다. 이 값은 실제 코드에서 stateObject.go의 getState() 및 setState() 함수의 매개변수로 사용되어 Slot을 지정하는 데 사용됩니다. 위의 두 함수를 더 깊게 살펴보면, 메모리에 해당 Slot의 캐시가 존재하지 않을 때 geth는 더 하위의 데이터베이스에서 이 Slot의 값을 가져오려고 시도한다는 것을 알 수 있습니다.

앞서 언급했듯이, Storage 계층은 하위 데이터를 접근하기 위한 인덱스 구조로 MPT(Merkle Patricia Trie) 구조를 사용합니다. MPT 트리의 균형을 유지하기 위해, 실제 구현에서는 Secure Trie라는 특별한 구조를 사용합니다. 일반적인 MPT와 달리, Secure Trie의 노드의 Key 값은 모두 해시되어야 합니다. 따라서 Secure Trie를 사용하여 필요한 데이터를 조회하거나 수정할 때는 해시된 값을 인덱스 키로 사용해야 하며, 이는 앞서 예제에서의 외부 해시 값에 해당합니다.

Secure Trie에 대한 자세한 설명은 Trie 장을 참고하시기 바랍니다. 요약하면, 상위 함수(stateObject) 호출에서는 키 값으로 Slot의 Position을 사용하고, 하위 함수(Trie) 호출에서는 키 값으로 Slot Position의 해시 값을 사용합니다.

```go
func (t *SecureTrie) TryGet(key []byte) ([]byte, error) {
// Secure Trie에서 조회하는 예제
// 여기서 key는 여전히 Slot의 Position입니다
// 그러나 더 하위의 함수 호출에서는 이 key의 해시 값을 조회에 사용하는 키 값으로 사용합니다.
  return t.trie.TryGet(t.hashKey(key))
}
```

### 계약 스토리지 사례 II: Sequence of Storage

이번에는 다른 예제를 살펴보겠습니다. 이 예제에서는 계약 내 변수의 선언 순서를 (number, number1, number2)에서 (number2, number1, number)로 조정했습니다. 계약 코드는 아래와 같습니다.

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

/**
 * @title Storage
 * @dev Store & retrieve value in a variable
 */
contract Storage {

    uint256 number2;
    uint256 number1;
    uint256 number;

    function stores(uint256 num) public {
        number = num;
        number1 = num + 1;
        number2 = num + 2;
    }
    
    function get_number() public view returns (uint256){
        return number;
    }
    
    function get_number1() public view returns (uint256){
        return number1;
    }
    
    function get_number2() public view returns (uint256){
        return number2;
    }
}
```

마찬가지로, 우리는 트랜잭션을 생성하여 계약의 `stores` 함수를 호출합니다. 이때 Storage 계층에서 이전과 다른 결과를 확인할 수 있습니다. number2 변수의 값이 첫 번째 Slot에 저장된 반면(Key: "0x0000000000000000000000000000000000000000000000000000000000000000"), number 변수의 값은 세 번째 Slot에 저장된 것을 확인할 수 있습니다(Key: "0x0000000000000000000000000000000000000000000000000000000000000002").

```json
{
  "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563": {
    "key": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "value": "0x0000000000000000000000000000000000000000000000000000000000000003"
    },
  "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6": {
    "key": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "value": "0x0000000000000000000000000000000000000000000000000000000000000002"
  },
  "0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace": {
    "key": "0x0000000000000000000000000000000000000000000000000000000000000002",
    "value": "0x0000000000000000000000000000000000000000000000000000000000000001"
  }
}
```

이 예제는 `go-ethereum`에서 변수의 저장 계층 Slot이 계약 내 선언 순서에 따라 첫 번째 Slot(position: 0)부터 할당된다는 것을 설명해줍니다.

### 계약 스토리지 사례 3: Partial Storage

다른 상황도 고려해보겠습니다. 세 개의 변수를 선언하지만, 그 중 두 개의 변수에만 값을 할당하는 경우입니다. 구체적으로는 number, number1, number2 순서로 세 개의 `uint256` 변수를 선언하되, 함수 `stores`에서는 number1과 number2에만 값을 할당합니다. 계약 코드는 다음과 같습니다.

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

/**
 * @title Storage
 * @dev Store & retrieve value in a variable
 */
contract Storage {
    uint256 number;
    uint256 number1;
    uint256 number2;

    function stores(uint256 num) public {
        number1 = num + 1;
        number2 = num + 2;
    }
    
    function get_number() public view returns (uint256){
        return number;
    }
    
    function get_number1() public view returns (uint256){
        return number1;
    }
    
    function get_number2() public view returns (uint256){
        return number2;
    }
}
```

위의 계약을 기반으로, 트랜잭션을 생성하여 `stores` 함수를 호출하고, 입력값을 1로 설정하여 `number1`과 `number2`의 값을 각각 2와 3으로 수정합니다. 트랜잭션이 완료된 후 Storage 계층 Slot의 결과는 다음과 같습니다.

```json
{
 "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6": {
  "key": "0x0000000000000000000000000000000000000000000000000000000000000001",
  "value": "0x0000000000000000000000000000000000000000000000000000000000000002"
 },
 "0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace": {
  "key": "0x0000000000000000000000000000000000000000000000000000000000000002",
  "value": "0x0000000000000000000000000000000000000000000000000000000000000003"
 }
}
```

`stores` 함수 실행 후 Storage 계층에서 위치가 1과 2인 두 개의 Slot에만 값이 할당된 것을 확인할 수 있습니다. 주목할 점은, 이 예제에서 Slot 할당이 0번 Slot이 아닌 1번 Slot부터 시작되었다는 것입니다. 이는 고정 길이 변수가 차지할 Slot 위치가 계약 초기화 시점에서 이미 할당된다는 것을 의미합니다. 변수들이 단순히 선언되었을 뿐 실제로 값이 할당되지 않았더라도, 해당 변수를 저장할 Slot은 EVM에 의해 이미 할당됩니다. 변수에 처음으로 값을 할당할 때 Slot이 새로 할당되는 것이 아니라는 점을 보여줍니다.

![Remix Debugger](../figs/01/remix.png)

### 계약 스토리지 사례 IV：Multiple Types

Solidity에는 **Address**라는 특별한 변수 유형이 있습니다. 이는 보통 계정의 주소 정보를 나타내는 데 사용됩니다. 예를 들어, ERC-20 계약에서 사용자가 보유한 토큰 정보는 (address -> uint) 형태의 맵 구조에 저장됩니다. 이 맵에서 key는 Address 타입으로, 사용자의 실제 주소를 나타냅니다. 현재 Address의 크기는 160비트(20바이트)로, 한 개 Slot(32바이트)을 가득 채우기에 충분하지 않습니다. 따라서 Address가 단독으로 value로 저장될 때는 Slot을 독점하지 않습니다. 이를 설명하기 위해 아래 예제를 사용합니다.

다음 예제에서는 세 개의 변수를 선언했습니다: number(uint256), addr(address), 그리고 isTrue(bool)입니다. 이더리움에서 Address 타입 변수의 길이는 20바이트이므로, Address 타입 변수는 전체 Slot(32바이트)을 채울 수 없습니다. 또한, 이더리움에서 부울(bool) 타입은 1비트(0 또는 1)만 필요합니다.

이제 트랜잭션을 생성하고 `storeaddr()` 함수를 호출하여 이 세 변수에 값을 할당해보겠습니다. 함수의 입력 매개변수는 하나의 uint256 값과 하나의 address 타입 값으로, 각각 {1, `0xb6186d3a3D32232BB21E87A33a4E176853a49d12`}입니다.

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

/**
 * @title Storage
 * @dev Store & retrieve value in a variable
 */
contract Storage {

    uint256 number;
    address addr;
    bool isTrue;

    function stores(uint256 num) public {
        // number1 = num + 1;
        // number2 = num + 2;
    }
    
    function storeaddr(uint256 num, address a) public {
        number = num;
        addr = a;
        isTure = true;
    }
    
    function get_number() public view returns (uint256){
        return number;
    }
    
}
```

트랜잭션 실행 후 Storage 계층의 결과는 아래 JSON과 같습니다. 이번 예제에서 계약은 세 개의 변수를 선언했지만, Storage 계층에서는 두 개의 Slot만 사용되었음을 알 수 있습니다. 첫 번째 Slot에는 uint256 값이 저장되어 있고, 두 번째 Slot(Key: `0x0000000000000000000000000000000000000000000000000000000000000001`)에는 `addr`와 `isTrue` 값이 저장되어 있습니다.

여기서 주목할 점은, 32바이트보다 작은 두 변수를 하나의 Slot에 합쳐 저장하는 방식이 물리적 공간을 절약하지만, 동시에 읽기/쓰기 확대 문제를 일으킬 수 있다는 것입니다. `Geth`에서는 읽기 연산의 최소 단위가 `32바이트`(이는 `OpSload` 명령어의 실제 호출에 따른 결과)입니다. 이 예제에서는 `isTrue`나 `addr` 변수 중 하나의 값만 읽고자 할 때에도 해당 Slot 전체를 메모리로 읽어와야 합니다. 마찬가지로 두 변수 중 하나의 값을 변경하고자 할 때에도 전체 Slot을 재기록해야 합니다. 이는 추가적인 비용을 발생시킵니다. 따라서 이더리움에서 32바이트 변수는 경우에 따라 더 작은 변수 타입(예: uint8)보다 가스 소비가 적을 수 있습니다. 이 점이 이더리움에서 32바이트 길이의 변수를 사용하도록 권장하는 이유이기도 합니다.

// Todo Gas cost? here or in EVM Section

```json
{
 "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563": {
  "key": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "value": "0x0000000000000000000000000000000000000000000000000000000000000001"
 },
 "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6": {
  "key": "0x0000000000000000000000000000000000000000000000000000000000000001",
  "value": "0x000000000000000000000001b6186d3a3d32232bb21e87a33a4e176853a49d12"
 }
}
```

### 계약 스토리지 사례 V: Storing Maps

가변 길이 배열과 Map 구조의 변수 저장 할당은 상대적으로 더 복잡합니다. Map은 본질적으로 `key-value` 구조이지만, Storage 계층에서는 map의 key 값이나 key 값의 sha3 해시를 직접 Storage 할당의 Slot 인덱스로 사용하지 않습니다. 현재 EVM에서는 map 요소의 key 값과 해당 Map 변수 선언 위치에 할당된 slot 값을 먼저 연결한 다음, 이 연결된 값의 `keccak256` 해시 값을 Slot의 위치 인덱스(Position)로 사용합니다. 아래 예제에서 이더리움이 Map과 같은 가변 길이 데이터 구조를 어떻게 처리하는지 보여드리겠습니다.

다음 계약에서는 고정 길이 uint256 타입의 객체 number와 [`string => uint256`] 타입의 Map 객체를 선언했습니다.

<!-- Todo: 가변 길이 데이터 구조의 저장 사례입니다. -->

```solidity
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

/**
 * @title Storage
 * @dev Store & retrieve value in a variable
 */
contract Storage {
    
    uint256 number;
    
    mapping(string => uint256) balances;

    function set_balance(uint256 num) public {
        number = num;
        balances["hsy"] = num;
        balances["lei"] = num + 1;
    }
    
    function get_number() public view returns (uint256){
        return number;
    }
    
}
```

우리는 `set_balance` 함수를 호출하는 트랜잭션을 구성합니다. 트랜잭션 실행 후 Storage 계층의 결과는 아래 JSON과 같습니다. 여기서, 고정 길이 변수 `number`는 첫 번째 Slot을 차지하고 있습니다(`Position: 0x0000000000000000000000000000000000000000000000000000000000000000`). 그러나 Map 타입 변수 balances가 포함하는 두 데이터는 물리적 순서대로 Slot에 저장되지 않았습니다. 또한, 이 두 값을 저장하는 Slot의 key도 Mapping에서 key의 직접적인 해시 값이 아님을 확인할 수 있습니다.

앞서 언급했듯이, EVM은 Map 요소의 key 값과 Map 변수에 할당된 Slot 위치를 연결하여 생성된 값을 `keccak256` 해시 함수로 계산하여 map 요소의 최종 저장 위치를 결정합니다. 예를 들어, 이 예제에서 `balances`라는 Map 변수는 변수 정의 순서에 따라 두 번째 Slot에 할당되며, 이 Slot의 Position은 1입니다. 따라서 `balances`의 각 key-value 쌍에 대한 Slot 위치는 `keccak(key, 1)`으로 결정됩니다. 여기서 (key, 1)은 특별한 연결 방식으로 결합된 값입니다.

```json
{
 "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563": {
  "key": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "value": "0x0000000000000000000000000000000000000000000000000000000000000001"
 },
 "0xa601d8e9cd2719ca27765dc16042655548d1ac3600a53ffc06b4a06a12b7c65c": {
  "key": "0xbaded3bf529b04b554de2e4ee0f5702613335896b4041c50a5555b2d5e279f91",
  "value": "0x0000000000000000000000000000000000000000000000000000000000000001"
 },
 "0x53ac6681d92653b13055d2e265b672e2db2b2a19407afb633928597f144edbb0": {
  "key": "0x56a8a0d158d59e2fd9317c46c65b1e902ed92f726ecfe82c06c33c015e8e6682",
  "value": "0x0000000000000000000000000000000000000000000000000000000000000002"
 }
}
```

위의 내용을 검증하기 위해 Go 언어로 작성된 코드로 관련 라이브러리를 호출하여 결론을 검증해 보았습니다. 예를 들어, balances["hsy"]에 할당된 Slot 위치는 아래 코드(../example/account/main.go)로 확인할 수 있습니다. 독자께서는 예제 코드를 참고하여 직접 시도해 볼 수 있습니다. 여기서 `k1`은 정수형 값으로, Storage 계층에서 Slot의 위치(Position)를 나타냅니다.

```go
k1 := solsha3.SoliditySHA3([]byte("hsy"), solsha3.Uint256(big.NewInt(int64(1))))
fmt.Printf("Test the Solidity Map storage Key1:         0x%x\n", k1)
```

## 요약
이번 장에서는 Go-Ethereum에서 Account라는 중요한 데이터 구조의 구현 세부 사항을 간단히 설명했습니다. 추가적인 세부 사항을 알고 싶다면 관련 부분의 소스 코드를 해당 장에서 참고하여 읽어보시기 바랍니다.
